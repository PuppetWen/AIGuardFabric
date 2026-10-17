import { Form, Button } from 'antd';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import PrivateLinkEndpointFields from './PrivateLinkEndpointFields';

beforeEach(async () => { await i18n.changeLanguage('en-US'); });
afterEach(async () => { cleanup(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
it('requires an explicitly supplied existing endpoint before configuration can be saved', async () => {
  const save = vi.fn(), invalid = vi.fn();
  render(<Form onFinish={save} onFinishFailed={invalid}>
    <PrivateLinkEndpointFields /><Button htmlType="submit">Save endpoint</Button>
  </Form>);
  const input = screen.getByRole('textbox', { name: 'Existing PrivateLink endpoint ID' });
  fireEvent.click(screen.getByRole('button', { name: 'Save endpoint' }));
  await waitFor(() => expect(invalid).toHaveBeenCalledTimes(1)); expect(save).not.toHaveBeenCalled();
  fireEvent.change(input, { target: { value: '   ' } }); fireEvent.click(screen.getByRole('button', { name: 'Save endpoint' }));
  await waitFor(() => expect(invalid).toHaveBeenCalledTimes(2)); expect(save).not.toHaveBeenCalled();
  fireEvent.change(input, { target: { value: 'ep-explicit-owned' } }); fireEvent.click(screen.getByRole('button', { name: 'Save endpoint' }));
  await waitFor(() => expect(save).toHaveBeenCalledWith({ settings: { endpoint_id: 'ep-explicit-owned' } }));
  expect(save).toHaveBeenCalledOnce();
});
it('provides the existing-resource instruction in Chinese without assigning a default target', async () => {
  await i18n.changeLanguage('zh-CN');
  render(<Form><PrivateLinkEndpointFields /></Form>);
  expect(screen.getByRole('textbox', { name: '已有 PrivateLink 端点 ID' })).toHaveValue('');
  expect(screen.getByText(/未填写不会自动选择/)).toBeInTheDocument();
});
