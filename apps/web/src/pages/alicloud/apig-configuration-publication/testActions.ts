import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect } from 'vitest';
export async function adopt() { fireEvent.click(await screen.findByRole('button', { name: 'Explicitly adopt the latest configuration observation' })); }
export async function prepare() {
  const button = screen.getByRole('button', { name: 'Prepare APIG configuration preview' });
  await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button); await screen.findByText('Trusted APIG configuration preview');
}
export async function confirm() {
  for (const name of [
    'Confirm the target and public configuration differences above',
    'Confirm public fields only, retaining other environments, credentials and private rules',
    'Confirm streaming-response and shared-resource impact remain unknown',
    'Confirm there is no cloud CAS; pre-write comparison cannot exclude external concurrency',
  ]) fireEvent.click(screen.getByRole('checkbox', { name }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Send one explicit new APIG configuration write' })).toBeEnabled());
}
export async function read(id: string) {
  const input = screen.getByRole('textbox', { name: 'APIG configuration original request UUID' });
  fireEvent.change(input, { target: { value: id } }); expect(input).toHaveValue(id);
  fireEvent.click(screen.getByRole('button', { name: 'Read original configuration receipt (GET only)' }));
  await screen.findByText('Original APIG configuration request receipt');
}
