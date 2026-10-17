import { fireEvent, screen, waitFor } from '@testing-library/react';
import { expect } from 'vitest';

export async function choose(label: 'Inventoried Worker / Team / CloudRole' | 'Actual platform Role UUID', option: string) {
  fireEvent.mouseDown(screen.getByRole('combobox', { name: label }));
  const choice = await screen.findByText(option, { selector: '.ant-select-item-option-content' }); fireEvent.click(choice);
}
export async function confirm(name: string, waitClosed = true) {
  const button = await screen.findByRole('button', { name });
  await waitFor(() => { expect(button).toBeVisible(); expect(button).toBeEnabled(); }); fireEvent.click(button);
  if (waitClosed) await waitFor(() => expect(screen.queryByRole('button', { name })).not.toBeInTheDocument());
}
export async function chooseActualMemberAndRole() {
  await choose('Inventoried Worker / Team / CloudRole', 'Actual Worker / Actual Team / Actual CloudRole');
  await choose('Actual platform Role UUID', 'Saved tenant viewer (viewer) · 01921d34-0000-7000-8000-000000000002');
}
export const consent = () => screen.getByRole('checkbox', { name: /Confirm constraining Keys bound to this Agent/ });
