import { Alert, Descriptions, Tag } from 'antd';
import { usePublicationText } from './text';
import type { Observation, Target } from './types';
export default function PublicationTarget({ target, observation }: { target: Target; observation?: Observation | null }) {
  const text = usePublicationText();
  return <>
    <Descriptions size="small" column={2} items={[
      { key: 'scope', label: text('目标范围 / 配置版本', 'Target scope / configuration version'), children: `${target.targetScopeId} / ${target.configurationVersion}` },
      { key: 'source', label: text('配置来源摘要', 'Configuration source label'), children: target.sourceLabel },
      { key: 'mode', label: text('实际模式', 'Effective mode'), children: <Tag color={target.transportMode === 'live' ? 'orange' : 'blue'}>{target.transportMode}</Tag> },
      { key: 'origin', label: 'Nacos origin', children: target.engineOrigin },
      { key: 'instance', label: text('地域 / 实例', 'Region / instance'), children: `${target.region} / ${target.instanceId}` },
      { key: 'namespace', label: 'Namespace', children: target.namespaceId === '' ? text('默认（空字符串）', 'Default (empty string)') : target.namespaceId },
      { key: 'tuple', label: 'Group / Data ID', children: `${target.group} / ${target.dataId}` },
      { key: 'dialect', label: text('协议', 'Dialect'), children: target.dialect },
    ]} />
    {observation && <Descriptions size="small" column={2} items={[
      { key: 'id', label: text('观察编号', 'Observation ID'), children: observation.id },
      { key: 'time', label: text('观察开始 / 完成', 'Observation started / completed'), children: `${observation.startedAt} / ${observation.observedAt}` },
      { key: 'md5', label: 'Content MD5', children: observation.contentMd5 },
      { key: 'hash', label: 'SHA256', children: observation.contentHash },
      { key: 'bytes', label: text('UTF-8 字节 / 空内容', 'UTF-8 bytes / empty content'), children: `${observation.contentBytes} / ${observation.contentEmpty}` },
      { key: 'usable', label: text('观察可用', 'Observation usable'), children: observation.usable ? text('是（仍需服务端复核）', 'Yes (subject to server verification)') : text('否', 'No') },
    ]} />}
    {observation?.reason && <Alert type="warning" message={observation.reason} />}
  </>;
}
