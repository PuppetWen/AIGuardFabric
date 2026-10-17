import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect } from 'vitest';
export const editor = () => screen.getByRole('textbox', { name: 'DAG declaration JSON' });
export const confirmOwnership = () => screen.getByRole('checkbox', { name: /Confirm this is an application-owned declaration/ });
export async function selectTeam() {
  const select = await screen.findByRole('combobox', { name: 'Observed Team' }); fireEvent.mouseDown(select);
  fireEvent.click(await screen.findByText('Owned Team', { selector: '.ant-select-item-option-content' }));
  await screen.findByRole('textbox', { name: 'DAG declaration JSON' });
}
export async function confirm(name: string, closed = true) {
  const button = await screen.findByRole('button', { name });
  await waitFor(() => { expect(button).toBeVisible(); expect(button).toBeEnabled(); }); fireEvent.click(button);
  if (closed) await waitFor(() => expect(screen.queryByRole('button', { name })).not.toBeInTheDocument());
}
export async function prepare() {
  if (!confirmOwnership().closest('.ant-checkbox')?.classList.contains('ant-checkbox-checked')) fireEvent.click(confirmOwnership());
  fireEvent.click(screen.getByRole('button', { name: 'Validate DAG and preview differences (no save)' }));
  await screen.findByText('Candidate differences');
}
export async function apply(closed = true) {
  fireEvent.click(screen.getByRole('button', { name: 'Commit the reviewed candidate' }));
  await confirm('Confirm committing the local fact', closed);
}
