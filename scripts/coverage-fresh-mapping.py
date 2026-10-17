"""本轮零 Hash 重复几何证明；原始 mismatch 事实永远保留。"""
import argparse
import hashlib
import json
import math
import re
import stat
from collections import Counter
from pathlib import Path

SCHEMA = 'agf.coverage-fresh-hash-zero-mapping.v1'
MODE = 'FreshHashZeroDuplicateMappingProof'
METRICS = {'lines', 'functions', 'instantiations', 'regions', 'branches', 'mcdc'}
COV_SHA = 'A00BE974FA188AEE2942C303145BC77CF5CD69ECD23135CF4A470E6517186D57'
PROF_SHA = '9990E978D4523095174C901ED1D5ED688A0D84321BC37E831A5364910380CA6C'
GATES = {'clippy-default', 'clippy-loopback', 'lib-default', 'api-tests', 'lib-loopback', 'alicloud-transports', 'managed-api', 'public-log-parsers', 'agent-tests', 'phase1-new-api', 'agent-core-docs', 'gateway-deferred-transport'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value):
    require(type(value) is int and value >= 0, 'Expected nonnegative JSON integer')
    return value


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=unique_pairs)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def plain(path):
    path = Path(path)
    require(path.is_absolute() and path.is_file(), 'Absolute ordinary file required')
    for ancestor in [path, *path.parents]:
        info = ancestor.lstat()
        require(not ancestor.is_symlink() and not (getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT), 'Reparse path refused')
    return path


def sha(path):
    with plain(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest().upper()


def reference(path):
    path = plain(path)
    return dict(Path=str(path), Sha256=sha(path), Length=path.stat().st_size)


def verify_ref(row):
    require(isinstance(row, dict) and re.fullmatch('[0-9A-F]{64}', row['Sha256']) is not None, 'SHA reference required')
    path = plain(row['Path'])
    require(sha(path) == row['Sha256'], 'Referenced bytes changed')
    if 'Length' in row:
        require(integer(row['Length']) == path.stat().st_size, 'Referenced length changed')
    return path


def inside(path, parent):
    require(Path(path).is_relative_to(Path(parent)), 'Path escaped owned scope')


def counted(row, length, positions, empty=False):
    require(isinstance(row, list) and len(row) == length, 'LLVM22 array shape differs')
    for value in row:
        integer(value)
    result = row.copy()
    for index in positions:
        require(not empty or row[index] == 0, 'Empty export contains nonzero count')
        result[index] = '<count>'
    return result


def region(row, length, positions, empty, filenames=None):
    result = counted(row, length, positions, empty)
    require(row[0] >= 1 and row[1] >= 1 and (row[2], row[3]) >= (row[0], row[1]), 'Invalid region coordinates')
    require(row[-1] in {0, 1, 2, 3, 4, 5, 6}, 'Unknown LLVM22 region kind')
    if filenames is not None:
        require(row[-3] < len(filenames) and row[-2] < len(filenames), 'Invalid region filename index')
    return result


def denominators(summary, empty):
    require(set(summary) == METRICS, 'LLVM22 metric set differs')
    result = {}
    for name, metric in summary.items():
        expected = {'count', 'covered', 'percent'} | ({'notcovered'} if name in {'regions', 'branches', 'mcdc'} else set())
        require(set(metric) == expected, 'Metric schema differs')
        result[name] = integer(metric['count'])
        covered = integer(metric['covered'])
        require(covered <= result[name] and (not empty or covered == 0), 'Invalid covered count')
        require(type(metric['percent']) in {int, float} and math.isfinite(metric['percent']) and 0 <= metric['percent'] <= 100, 'Metric percent invalid')
        if 'notcovered' in metric:
            require(integer(metric['notcovered']) == result[name] - covered, 'Metric remainder differs')
    return result


def mcdc(rows, empty, filenames=None):
    result = []
    for row in rows:
        require(isinstance(row, list) and len(row) == 11, 'LLVM22 MC/DC shape differs')
        require(isinstance(row[9], list) and all(type(v) is bool for v in row[9]), 'MC/DC independence schema differs')
        require(isinstance(row[10], list), 'MC/DC vectors schema differs')
        for vector in row[10]:
            require(set(vector) == {'executed', 'result', 'conditions'} and vector['executed'] is True, 'MC/DC vector schema differs')
            require(vector['result'] is None or type(vector['result']) is bool, 'MC/DC result invalid')
            require(isinstance(vector['conditions'], list) and len(vector['conditions']) == len(row[9]) and all(v is None or type(v) is bool for v in vector['conditions']), 'MC/DC condition invalid')
        # MC/DC outcomes are profile-dependent. Preserve them exactly rather than silently masking.
        result.append(region(row[:9], 9, (4, 5), empty, filenames) + row[9:])
    return result


def expansion(row, empty):
    require(set(row) == {'filenames', 'source_region', 'target_regions', 'branches'}, 'Expansion schema differs')
    filenames = row['filenames']
    require(isinstance(filenames, list) and filenames and all(type(f) is str and f for f in filenames), 'Expansion filenames invalid')
    return dict(filenames=filenames, source_region=region(row['source_region'], 8, (4,), empty, filenames),
        target_regions=[region(r, 8, (4,), empty, filenames) for r in row['target_regions']],
        branches=[region(r, 9, (4, 5), empty, filenames) for r in row['branches']])


def geometry(document, empty=False):
    require(set(document) == {'type', 'version', 'data'}, 'Unknown top-level LLVM22 schema field')
    require(document['type'] == 'llvm.coverage.json.export' and document['version'] == '3.1.0' and len(document['data']) == 1, 'Exact LLVM22 export schema required')
    data = document['data'][0]
    require(set(data) == {'functions', 'files', 'totals'}, 'Complete export fields required')
    functions, files, segments, names = Counter(), Counter(), Counter(), {}
    removed = []
    for function in data['functions']:
        require(set(function) == {'name', 'count', 'filenames', 'regions', 'branches', 'mcdc_records'}, 'Function schema differs')
        name, filenames = function['name'], function['filenames']
        require(type(name) is str and bool(name) and isinstance(filenames, list) and bool(filenames) and all(type(f) is str and f for f in filenames), 'Function identity missing')
        count = integer(function['count'])
        require(not empty or count == 0, 'Empty function execution count differs')
        require(isinstance(function['regions'], list) and bool(function['regions']), 'Function region geometry missing')
        code_regions = 0
        for item in function['regions']:
            region(item, 8, (4,), empty, filenames)
            code_regions += item[7] == 0
        if count > 0 and code_regions:
            names[name] = names.get(name, 0) + 1
        functions[canonical(dict(name=name, filenames=filenames,
            regions=[region(r, 8, (4,), empty, filenames) for r in function['regions']],
            branches=[region(r, 9, (4, 5), empty, filenames) for r in function['branches']],
            mcdc_records=mcdc(function['mcdc_records'], empty, filenames)))] += 1
    for file in data['files']:
        require(set(file) == {'filename', 'segments', 'branches', 'mcdc_records', 'expansions', 'summary'}, 'File schema differs')
        require(type(file['filename']) is str and bool(file['filename']), 'File identity missing')
        files[canonical(dict(filename=file['filename'], denominators=denominators(file['summary'], empty),
            branches=[region(r, 9, (4, 5), empty) for r in file['branches']], mcdc_records=mcdc(file['mcdc_records'], empty),
            expansions=[expansion(r, empty) for r in file['expansions']]))] += 1
        output, raw_previous = [], []
        for index, segment in enumerate(file['segments']):
            require(isinstance(segment, list) and len(segment) == 6 and all(type(v) is bool for v in segment[3:]), 'Segment schema differs')
            counted(segment[:3], 3, (2,), empty)
            require(segment[0] >= 1 and segment[1] >= 1, 'Segment coordinates invalid')
            normalized = segment.copy(); normalized[2] = 0
            # HasCount=true 证明不是 EmitSkippedRegion，严格只重放官方这一确定分支。
            if not empty and output and normalized[3] and output[-1][3] and not normalized[4] and not output[-1][4]:
                removed.append(dict(Filename=file['filename'], Index=index, Previous=raw_previous[-1], Removed=segment))
                continue
            output.append(normalized); raw_previous.append(segment)
        segments[canonical(dict(filename=file['filename'], segments=output))] += 1
    require(functions and files, 'Export geometry cannot be empty')
    return dict(Functions=functions, Files=files, Segments=segments, Names=names,
        Totals=denominators(data['totals'], empty), RemovedSegments=removed)


def classify(stderr, dump=False):
    counts, names = [], Counter()
    for line in Path(stderr).read_text(encoding='utf-8-sig').splitlines():
        if not line.strip():
            continue
        total = re.fullmatch(r'warning: ([0-9]+) functions have mismatched data', line)
        item = re.fullmatch(r"hash-mismatch: No profile record found for '([^'\r\n]+)' with hash = 0x([0-9a-fA-F]+)", line)
        if total:
            counts.append(int(total[1]))
        elif dump and item:
            require(int(item[2], 16) == 0, 'Nonzero hash mismatch refused')
            names[item[1]] += 1
        else:
            raise ValueError('Unknown or malformed LLVM warning')
    require(len(counts) == 1 and counts[0] > 0, 'One positive raw mismatch count required')
    require(not dump or sum(names.values()) == counts[0], 'Dump mismatch details/count differ')
    return counts[0], names


def command_files(command, reports):
    require(type(command['exitCode']) is int and command['exitCode'] == 0, 'Actual command failed')
    for key, suffix in [('response', '.rsp'), ('stdout', '.log'), ('stderr', '.stderr.log')]:
        require(command[key] == str(Path(reports) / (command['name'] + suffix)), 'Command evidence escaped reports')
        verify_ref(dict(Path=command[key], Sha256=command[key + 'Sha256']))
    expected = ''.join('"' + arg + '"\n' for arg in command['arguments'])
    require(Path(command['response']).read_text(encoding='utf-8-sig') == expected, 'Response argv differs')
    require(command['programSha256'] == COV_SHA and sha(command['program']) == COV_SHA, 'LLVM22 tool changed')


def inputs(context):
    require(context['Policy'] == MODE and re.fullmatch('[0-9a-f]{32}', context['RunId']) is not None, 'Explicit fresh proof policy/run required')
    root, target, reports = Path(context['Root']), Path(context['Target']), Path(context['Reports'])
    inside(target, root); inside(reports, root)
    native_path = verify_ref(context['NativeReceipt']); native = load(native_path)
    require(native_path.name == context['NativeReceiptName'] and native['Status'] == 'PASS' and native['Completed'] is True and native['RustInputsUnchanged'] is True and len(native['Gates']) == 12, 'Native terminal proof incomplete')
    require({g['Gate'] for g in native['Gates']} == GATES, 'Native exact twelve gate names differ')
    native_inputs = verify_ref(context['NativeInputs'])
    require(context['SourceState'] == context['NativeInputs'] and native['RustInputsManifestSha256'] == context['NativeInputs']['Sha256'] and Path(native['RustInputsManifest']) == native_inputs, 'Native source binding differs')
    rows = load(native_inputs); require(isinstance(rows, list) and len(rows) == native['RustInputCount'], 'Native input count differs')
    seen = set()
    for row in rows:
        relative = row['Path']
        require(type(relative) is str and relative not in seen and '\\' not in relative and ':' not in relative and all(p not in {'', '.', '..'} for p in relative.split('/')) and not Path(relative).is_absolute(), 'Native relative source escaped/duplicated')
        seen.add(relative); verify_ref(dict(Path=str(root / relative), Sha256=row['Sha256']))
    for gate in native['Gates']:
        require(type(gate['ExitCode']) is int and gate['ExitCode'] == 0, 'Native gate failed')
        verify_ref(dict(Path=gate['Log'], Sha256=gate['Sha256']))
    artifacts = load(verify_ref(context['CurrentArtifacts']))
    require(artifacts['Schema'] == 'agf.coverage-current-workspace-artifacts.v1' and artifacts['Mode'] == 'CurrentWorkspaceArtifacts', 'Current artifacts schema differs')
    require(artifacts['Compile']['ObjectSetSha256'] == artifacts['Tests']['ObjectSetSha256'] == context['ObjectSetSha256'], 'Current compile/test objects differ')
    require(artifacts['Compile']['ProducerSetSha256'] == artifacts['Tests']['ProducerSetSha256'] and artifacts['Tests']['Objects'] == context['Objects'], 'Current producer/objects differ')
    require(context['Objects'], 'Empty current object set')
    seen = set()
    for row in context['Objects']:
        path = verify_ref(row); inside(path, target)
        require(path.suffix.lower() in {'.exe', '.dll'} and str(path) not in seen, 'Invalid current object identity')
        seen.add(str(path))
    profiles = context['Profiles']; require(isinstance(profiles, dict) and profiles, 'Fresh profile map required')
    for path, digest in profiles.items():
        file = verify_ref(dict(Path=path, Sha256=digest))
        require(file.parent == target and re.fullmatch(re.escape(context['RunId']) + r'-[0-9]+-[0-9]+_[0-9]+\.profraw', file.name) is not None, 'Profile not owned by fresh run')
    actual_profiles = set()
    for parent, directories, filenames in target.walk(follow_symlinks=False):
        for name in directories:
            item = parent / name
            require(not item.is_symlink() and not (getattr(item.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT), 'Profile tree reparse refused')
        for name in filenames:
            if name.endswith('.profraw'):
                actual_profiles.add(str(plain(parent / name)))
    require(actual_profiles == set(profiles), 'Fresh complete profile set changed')
    verify_ref(context['Merged']); inside(context['Merged']['Path'], reports)
    tools = context['ReviewedLlvmTools']
    require(tools['covSha256'] == COV_SHA and tools['profdataSha256'] == PROF_SHA and sha(tools['cov']) == COV_SHA and sha(tools['profdata']) == PROF_SHA, 'Reviewed tools differ')
    verify_ref(dict(Path=tools['manifest'], Sha256=tools['manifestSha256']))
    verify_ref(context['Python']); verify_ref(context['Analyzer'])
    require(Path(context['Analyzer']['Path']) == Path(__file__).resolve(), 'Exact analyzer required')
    return root, target, reports


def analyze(context_path, commands_path):
    initial_refs = [reference(context_path), reference(commands_path)]
    context, commands = load(context_path), load(commands_path)
    root, target, reports = inputs(context)
    expected_names = ['fresh-mapping-dump', 'fresh-mapping-full', 'fresh-mapping-empty']
    require([row['name'] for row in commands] == expected_names, 'Three exact diagnostic exports required')
    raw = context['FourReportCommands']; results = context['FourReportResults']
    require([r['name'] for r in raw] == ['summary', 'summary-json', 'lcov', 'html'] and len(results) == 4, 'Four actual report results required')
    counts = []
    for command, result in zip(raw, results):
        command_files(command, reports)
        require(result['name'] == command['name'] and type(result['effectiveExitCode']) is int and result['effectiveExitCode'] == 0 and result['zeroMismatchedData'] is False and result['mode'] == 'CurrentWorkspaceArtifacts', 'Raw mismatch facts differ')
        require(result['objectSetSha256'] == context['ObjectSetSha256'] and result['objectCount'] == len(context['Objects']), 'Raw current object binding differs')
        counts.append(classify(command['stderr'])[0])
    base = raw[1]['arguments']
    require(base[0] == '-format=text' and base[1] == '-instr-profile=' + context['Merged']['Path'] and base[-1] == '-summary-only', 'Original export options differ')
    paths = ['-object', None] * len(context['Objects'])
    for index, row in enumerate(context['Objects']):
        paths[index * 2 + 1] = str(Path(row['Path']).relative_to(root))
    require(base[2:-3] == paths and base[-3] == '-ignore-filename-regex', 'Original complete objects/filter differ')
    expected = [base + ['-dump', '-num-threads=1'], base[:-1], [base[0], '-empty-profile', *base[2:-1]]]
    for command, arguments in zip(commands, expected):
        command_files(command, reports)
        require(command['subcommand'] == 'export' and command['arguments'] == arguments and command['program'] == context['ReviewedLlvmTools']['cov'], 'Diagnostic option delta differs')
    count, names = classify(commands[0]['stderr'], True)
    require(all(value == count for value in counts) and classify(commands[1]['stderr'])[0] == count, 'Raw and diagnostic warning counts differ')
    require(Path(commands[2]['stderr']).read_bytes() == b'', 'Empty export stderr is not empty')
    full, empty = load(commands[1]['stdout']), load(commands[2]['stdout'])
    actual, zero = geometry(full), geometry(empty, True)
    summary = load(raw[1]['stdout'])
    require(summary['type'] == full['type'] and summary['version'] == full['version'] and len(summary['data']) == 1 and summary['data'][0]['totals'] == full['data'][0]['totals'], 'Actual full/summary totals differ')
    require(set(summary['data'][0]) == {'files', 'totals'} and all(set(f) == {'filename', 'summary'} for f in summary['data'][0]['files']), 'Raw summary schema differs')
    require(Counter(canonical(f) for f in summary['data'][0]['files']) == Counter(canonical(dict(filename=f['filename'], summary=f['summary'])) for f in full['data'][0]['files']), 'Actual full/summary per-file metrics differ')
    require(all(name in actual['Names'] for name in names), 'Mismatch name has no positive valid current mapping')
    checks = dict(FunctionGeometryMultisetEqual=actual['Functions'] == zero['Functions'],
        FileGeometryAndSixDenominatorsEqual=actual['Files'] == zero['Files'], TotalSixDenominatorsEqual=actual['Totals'] == zero['Totals'],
        AllOrderedSegmentsEqualAfterOfficialZeroCollapse=actual['Segments'] == zero['Segments'])
    require(all(checks.values()), 'Complete fresh geometry or denominator comparison failed')
    bindings = [*initial_refs, context['CurrentArtifacts'], context['NativeReceipt'], context['NativeInputs'], context['Merged'], context['Python'], context['Analyzer']]
    for command in raw + commands:
        bindings.extend(reference(command[key]) for key in ['response', 'stdout', 'stderr'])
    for row in initial_refs:
        verify_ref(row)
    inputs(context)
    return dict(Schema=SCHEMA, Status='PROVEN', Accepted=True, Mode=MODE, StrongZeroMismatch=False,
        RawReportZeroMismatch=False, RawMismatchCount=count, UniqueMismatchNames=len(names), NonZeroHashMismatchCount=0,
        AllNamesHavePositiveValidMapping=True, Checks=checks, Totals=actual['Totals'],
        FunctionRows=sum(actual['Functions'].values()), FileRows=sum(actual['Files'].values()),
        ObjectSetSha256=context['ObjectSetSha256'], ProfileSetSha256=context['ProfileSetSha256'],
        NativeInputsSha256=context['NativeInputs']['Sha256'], NativeReceiptSha256=context['NativeReceipt']['Sha256'],
        ExactMismatchNames=[dict(Name=name, Occurrences=number, PositiveValidInstances=actual['Names'][name]) for name, number in sorted(names.items())],
        RemovedSegmentBoundaries=actual['RemovedSegments'], InputAndOutputRefs=bindings,
        WarningWaiverGranted=False, OldFailureReclassified=False, CoverageAcceptanceClaimed=False,
        ScientificScope='This exact fresh object/profile set; not all hash-zero mappings or historical runs')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['analyze', 'verify'])
    parser.add_argument('--context', required=True, type=Path)
    parser.add_argument('--commands', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--proof', type=Path)
    parser.add_argument('--proof-sha256')
    args = parser.parse_args()
    proof = analyze(args.context, args.commands)
    if args.mode == 'verify':
        verify_ref(dict(Path=str(args.proof), Sha256=args.proof_sha256))
        require(load(args.proof) == proof, 'Saved proof differs from complete fresh recomputation')
    else:
        with args.output.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(Accepted=True, Mode=MODE, StrongZeroMismatch=False, RawMismatchCount=proof['RawMismatchCount']), ensure_ascii=False))


if __name__ == '__main__':
    main()
