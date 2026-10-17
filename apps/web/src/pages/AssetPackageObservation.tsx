import { Alert, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { AssetProfile } from '@/types/domain';

export function AssetPackageObservation({ observation }: { observation: AssetProfile['packageObservation'] }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const current = observation?.current;
  if (!current) return null;
  const reasons: Record<string, string> = {
    unreadable: text('文件、目录或元数据无法读取，也可能正被其他程序写入。', 'A file, directory or metadata could not be read, or another program is writing it.'),
    'too-large': text('单文件超过 4 MiB，或目录文件总量超过 64 MiB。', 'A file exceeds 4 MiB or the package exceeds 64 MiB.'),
    'too-many-entries': text('超过 4096 个文件，或文件与子目录合计超过 8192 项。', 'More than 4096 files or 8192 file and directory entries.'),
    'too-deep': text('相对路径超过 16 层。', 'A relative path exceeds 16 levels.'),
    'unsupported-path': text('文件名无法转换为支持的路径格式。', 'A filename cannot be represented in the supported path format.'),
    'not-regular-file': text('存在非普通文件，或缺少 SKILL.md。', 'A non-regular file was found, or SKILL.md is missing.'),
    'changed-during-read': text('读取期间内容或目录结构变化，下次采集会重试。', 'Content or the directory inventory changed while reading; the next collection retries.'),
    'link-not-allowed': text('包含符号链接、目录联接或其他 Windows 重解析点；不会沿链接读取。', 'A symbolic link, junction or other Windows reparse point was found; linked content is not followed.'),
  };
  const complete = current.status === 'verified' && !!current.sha256;
  const date = (value?: string) => value ? new Date(value).toLocaleString(zh ? 'zh-CN' : 'en-US') : '—';
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text strong>{text('最近 Skill 目录观察', 'Latest Skill directory observation')}</Typography.Text>
    <Typography.Text>{text('平台接收时间：', 'Received: ')}{date(observation?.receivedAt)}</Typography.Text>
    {complete ? <>
      <Typography.Text>{text('已完整读取', 'Complete observation')} · {current.files} {text('个文件', 'files')} · {current.bytes?.toLocaleString()} {text('字节', 'bytes')}</Typography.Text>
      <Typography.Paragraph copyable style={{ overflowWrap: 'anywhere' }}>{current.algorithm}: {current.sha256}</Typography.Paragraph>
    </> : <>
      <Alert type="warning" showIcon message={text('本次未取得完整目录哈希', 'Complete directory hash unavailable')}
        description={reasons[current.status] ?? current.status} />
      {observation?.lastVerified?.sha256 && <div>
        <Typography.Text>{text('上次完整观察（历史记录）：', 'Last complete observation (historical): ')}{date(observation.lastVerifiedAt)}</Typography.Text>
        <Typography.Paragraph copyable style={{ overflowWrap: 'anywhere' }}>{observation.lastVerified.sha256}</Typography.Paragraph>
      </div>}
    </>}
    <Typography.Paragraph type="secondary">{text(
      '包含 SKILL.md、子目录脚本、隐藏文件、文件名和空目录。首次目录观察建立基线；后续哈希变化需要核对，不自动认定恶意。读取失败后保留上次完整观察用于恢复时比较。此观察不是实时监控或原子快照，不含权限、ACL 和 NTFS 备用数据流。',
      'Includes SKILL.md, nested scripts, hidden files, filenames and empty directories. The first observation establishes a baseline; later hash changes require review and do not prove malicious activity. The last complete observation remains available for comparison after a read failure. This is neither live monitoring nor an atomic snapshot; permissions, ACLs and NTFS alternate data streams are excluded.',
    )}</Typography.Paragraph>
  </Space>;
}
