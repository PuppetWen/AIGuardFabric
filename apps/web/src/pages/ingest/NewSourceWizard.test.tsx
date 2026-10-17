import { useState } from 'react';
import { Form } from 'antd';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { logSourcesApi } from '@/api/logSources';
import { NewSourceWizard } from './NewSourceWizard';
import type { NewSourceValues } from './ingest.data';

function Wizard() {
  const [form] = Form.useForm<NewSourceValues>();
  const [step, setStep] = useState(0);
  return <NewSourceWizard open form={form} step={step} setStep={setStep} parsers={[]}
    onClose={() => undefined} onResetForm={() => undefined} onRefetch={() => undefined} />;
}

describe('log source registration', () => {
  it('preserves pull protocol and connection fields across wizard steps and reports save errors', async () => {
    const save = vi.spyOn(logSourcesApi, 'save').mockRejectedValue(new Error('上游配置未保存'));
    render(<Wizard />);
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('HTTP Pull · 定时拉取平台日志 API'));
    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    fireEvent.change(await screen.findByLabelText('日志源名称'), { target: { value: '业务平台日志' } });
    fireEvent.change(await screen.findByLabelText('上游日志 API 地址'), { target: { value: 'https://logs.example.test/events' } });
    fireEvent.change(screen.getByLabelText('认证请求头（JSON，可选）'), { target: { value: '{"Authorization":"Bearer fixture-only"}' } });
    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    await screen.findByText('https://logs.example.test/events');
    fireEvent.click(screen.getByRole('button', { name: '保存并接入' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith({
      name: '业务平台日志', protocol: 'http-pull', endpoint: 'https://logs.example.test/events', nativeReceiver: undefined,
      parserId: undefined, enabled: true, pollIntervalSecs: 60, headers: { Authorization: 'Bearer fixture-only' },
    }, undefined));
    await screen.findByText('上游配置未保存');
    save.mockRestore();
  });

  it('keeps the native receiver binding while navigating and saving', async () => {
    const save = vi.spyOn(logSourcesApi, 'save').mockRejectedValue(new Error('保留草稿'));
    render(<Wizard />);
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('原生接收器 · Syslog / Kafka / OTLP / MQTT 等'));
    fireEvent.mouseDown(await screen.findByLabelText('接收器'));
    fireEvent.click((await screen.findAllByText('syslog-udp')).at(-1)!);
    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    fireEvent.change(await screen.findByLabelText('日志源名称'), { target: { value: '分支防火墙' } });
    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    await screen.findByText('syslog-udp');
    fireEvent.click(screen.getByRole('button', { name: '保存并接入' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      name: '分支防火墙', protocol: 'native', nativeReceiver: 'syslog-udp', enabled: true,
    }), undefined));
    await screen.findByText('保留草稿');
    save.mockRestore();
  });

  it('preserves reviewed CIDRs and certificate requirements when saving fails', async () => {
    const save = vi.spyOn(logSourcesApi, 'save').mockRejectedValue(new Error('来源配置未保存'));
    render(<Wizard />);
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('原生接收器 · Syslog / Kafka / OTLP / MQTT 等'));
    fireEvent.mouseDown(await screen.findByLabelText('接收器'));
    fireEvent.click((await screen.findAllByText('syslog-tls')).at(-1)!);
    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    fireEvent.change(await screen.findByLabelText('日志源名称'), { target: { value: '企业证书接入' } });
    fireEvent.change(screen.getByLabelText('允许的来源网段（CIDR）'), { target: { value: '192.0.2.0/24\n2001:db8::/32' } });
    fireEvent.click(screen.getByRole('switch', { name: '要求已验证的客户端证书' }));
    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    await screen.findByText(/192\.0\.2\.0\/24/);
    fireEvent.click(screen.getByRole('button', { name: '保存并接入' }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({
      nativeReceiver: 'syslog-tls', allowedCidrs: ['192.0.2.0/24', '2001:db8::/32'], requireMtls: true,
    }), undefined));
    await screen.findByText('来源配置未保存');
    fireEvent.click(screen.getByRole('button', { name: '上一步' }));
    expect(await screen.findByLabelText('允许的来源网段（CIDR）')).toHaveValue('192.0.2.0/24\n2001:db8::/32');
    expect(screen.getByRole('switch', { name: '要求已验证的客户端证书' })).toBeChecked();
    save.mockRestore();
  });
});
