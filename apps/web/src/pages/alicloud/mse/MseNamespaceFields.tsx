import { Form, Input, Select } from 'antd';
import { useTranslation } from 'react-i18next';

export default function MseNamespaceFields() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const form = Form.useFormInstance();
  const selection = Form.useWatch('mseNamespaceSelection', form) as string | undefined;
  return <>
    <Form.Item name={['settings', 'instance_id']} label={text('MSE 实例 ID', 'MSE instance ID')}
      rules={[{ required: true, whitespace: true }]}><Input /></Form.Item>
    <Form.Item name="mseNamespaceSelection" label={text('Nacos 命名空间选择', 'Nacos namespace selection')}
      extra={text('须明确选择。默认命名空间发送空字符串；未选择不会自动视为默认。', 'Choose explicitly. Default sends an empty string; an unselected value is not the default.')}
      rules={[{ required: true }]}><Select aria-label={text('Nacos 命名空间选择', 'Nacos namespace selection')}
        placeholder={text('请选择命名空间方式', 'Select namespace mode')} options={[
          { value: 'default', label: text('默认命名空间', 'Default namespace') },
          { value: 'specific', label: text('指定命名空间 ID', 'Specific namespace ID') },
        ]} /></Form.Item>
    {selection === 'specific' && <Form.Item name={['settings', 'namespace_id']} label={text('Nacos 命名空间 ID', 'Nacos namespace ID')}
      rules={[{ required: true, whitespace: true }]}><Input /></Form.Item>}
  </>;
}
