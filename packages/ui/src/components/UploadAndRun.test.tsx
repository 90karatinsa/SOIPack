import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';

import { UploadAndRun } from './UploadAndRun';
import type { PipelineLogEntry } from '../types/pipeline';

const baseLogs: PipelineLogEntry[] = [];

const createProps = (overrides: Partial<ComponentProps<typeof UploadAndRun>> = {}) => ({
  files: [],
  onFilesChange: jest.fn(),
  logs: baseLogs,
  isEnabled: true,
  onRun: jest.fn(),
  isRunning: false,
  canRun: true,
  jobStates: [],
  error: null,
  lastCompletedAt: null,
  independentSources: [],
  independentArtifacts: [],
  onIndependentSourcesChange: jest.fn(),
  onIndependentArtifactsChange: jest.fn(),
  ...overrides,
});

describe('UploadAndRun', () => {
  it('notifies when independent sources toggles change', async () => {
    const user = userEvent.setup();
    const onIndependentSourcesChange = jest.fn();
    const { rerender } = render(
      <UploadAndRun
        {...createProps({ onIndependentSourcesChange })}
      />,
    );

    const jiraCheckbox = screen.getByRole('checkbox', { name: /Jira CSV/i });
    await user.click(jiraCheckbox);
    expect(onIndependentSourcesChange).toHaveBeenCalledWith(['jiraCsv']);

    onIndependentSourcesChange.mockClear();
    rerender(
      <UploadAndRun
        {...createProps({
          independentSources: ['jiraCsv'],
          onIndependentSourcesChange,
        })}
      />,
    );
    await user.click(screen.getByRole('checkbox', { name: /Jira CSV/i }));
    expect(onIndependentSourcesChange).toHaveBeenCalledWith([]);
  });

  it('notifies when independent artifact toggles change', async () => {
    const user = userEvent.setup();
    const onIndependentArtifactsChange = jest.fn();
    const { rerender } = render(
      <UploadAndRun
        {...createProps({ onIndependentArtifactsChange })}
      />,
    );

    const analysisCheckbox = screen.getByRole('checkbox', { name: /Analiz artefaktları/i });
    await user.click(analysisCheckbox);
    expect(onIndependentArtifactsChange).toHaveBeenCalledWith(['analysis']);

    onIndependentArtifactsChange.mockClear();
    rerender(
      <UploadAndRun
        {...createProps({
          independentArtifacts: ['analysis'],
          onIndependentArtifactsChange,
        })}
      />,
    );

    await user.click(screen.getByRole('checkbox', { name: /Analiz artefaktları/i }));
    expect(onIndependentArtifactsChange).toHaveBeenCalledWith([]);
  });
});
