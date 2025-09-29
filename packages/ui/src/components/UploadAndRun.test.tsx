import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ComponentProps } from 'react';

import { UploadAndRun } from './UploadAndRun';
import type { PipelineLogEntry } from '../types/pipeline';
import type {
  DoorsNextConnectorFormState,
  JamaConnectorFormState,
  JenkinsConnectorFormState,
  PolarionConnectorFormState,
  UploadRunPayload,
} from '../types/connectors';

const baseLogs: PipelineLogEntry[] = [];

const createPolarionState = (): PolarionConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectId: '',
  username: '',
  password: '',
  token: '',
});

const createJenkinsState = (): JenkinsConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  job: '',
  build: '',
  username: '',
  password: '',
  token: '',
});

const createDoorsNextState = (): DoorsNextConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectArea: '',
  username: '',
  password: '',
  accessToken: '',
});

const createJamaState = (): JamaConnectorFormState => ({
  enabled: false,
  baseUrl: '',
  projectId: '',
  token: '',
});

const createProps = (overrides: Partial<ComponentProps<typeof UploadAndRun>> = {}) => ({
  files: [],
  onFilesChange: jest.fn(),
  logs: baseLogs,
  isEnabled: true,
  onRun: jest.fn<(payload: UploadRunPayload) => void>(),
  isRunning: false,
  canRun: true,
  jobStates: [],
  error: null,
  lastCompletedAt: null,
  independentSources: [],
  independentArtifacts: [],
  onIndependentSourcesChange: jest.fn(),
  onIndependentArtifactsChange: jest.fn(),
  polarion: createPolarionState(),
  onPolarionChange: jest.fn(),
  jenkins: createJenkinsState(),
  onJenkinsChange: jest.fn(),
  doorsNext: createDoorsNextState(),
  onDoorsNextChange: jest.fn(),
  jama: createJamaState(),
  onJamaChange: jest.fn(),
  packJobStatus: null,
  postQuantumSignature: null,
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

  it('submits sanitized connector payloads when running the pipeline', async () => {
    const user = userEvent.setup();
    const onRun = jest.fn();

    let polarion = createPolarionState();
    let jenkins = createJenkinsState();
    let doorsNext = createDoorsNextState();
    let jama = createJamaState();

    let rerenderComponent = () => {};

    const buildProps = () =>
      createProps({
        files: [new File(['dummy'], 'requirements.reqif', { type: 'application/xml' })],
        onRun,
        polarion,
        onPolarionChange: (next: PolarionConnectorFormState) => {
          polarion = next;
          rerenderComponent();
        },
        jenkins,
        onJenkinsChange: (next: JenkinsConnectorFormState) => {
          jenkins = next;
          rerenderComponent();
        },
        doorsNext,
        onDoorsNextChange: (next: DoorsNextConnectorFormState) => {
          doorsNext = next;
          rerenderComponent();
        },
        jama,
        onJamaChange: (next: JamaConnectorFormState) => {
          jama = next;
          rerenderComponent();
        },
      });

    const { rerender } = render(<UploadAndRun {...buildProps()} />);
    rerenderComponent = () => rerender(<UploadAndRun {...buildProps()} />);

    await user.click(screen.getByRole('checkbox', { name: /Polarion ALM/i }));
    await user.type(screen.getByLabelText(/Polarion URL/i), ' https://polarion.example.com ');
    await user.type(screen.getByLabelText(/Proje kimliği/i), ' AVIONICS ');
    await user.type(screen.getByLabelText(/^Kullanıcı adı$/i), ' alice ');
    await user.type(screen.getByLabelText(/^Parola$/i), ' secret ');
    await user.type(screen.getByLabelText(/Erişim token/i), ' polarion-token ');

    await user.click(screen.getByRole('checkbox', { name: /^Jenkins$/i }));
    await user.type(screen.getByLabelText(/Jenkins URL/i), 'https://jenkins.example.com/');
    await user.type(screen.getByLabelText(/Job adı/i), ' soipack-ci ');
    await user.type(screen.getByLabelText(/Build numarası/i), '42');
    await user.type(screen.getByLabelText(/^Kullanıcı adı$/i, { selector: '#connector-jenkins-username' }), ' bob ');
    await user.type(screen.getByLabelText(/^Parola$/i, { selector: '#connector-jenkins-password' }), ' password ');
    await user.type(screen.getByLabelText(/API token/i), ' jenkins-token ');

    await user.click(screen.getByRole('checkbox', { name: /DOORS Next/i }));
    await user.type(screen.getByLabelText(/Sunucu URL/i), 'https://doors.example.com');
    await user.type(screen.getByLabelText(/Project area/i), ' DO-178C ');
    await user.type(screen.getByLabelText(/^Kullanıcı adı$/i, { selector: '#connector-doorsnext-username' }), ' dng ');
    await user.type(screen.getByLabelText(/^Parola$/i, { selector: '#connector-doorsnext-password' }), ' dng-pass ');
    await user.type(screen.getByLabelText(/OSLC token/i), ' doors-token ');

    await user.click(screen.getByRole('checkbox', { name: /Jama Connect/i }));
    await user.type(screen.getByLabelText(/Jama URL/i), 'https://jama.example.com');
    await user.type(screen.getByLabelText(/Proje kimliği/i, { selector: '#connector-jama-project' }), '123');
    await user.type(screen.getByLabelText(/REST token/i), ' jama-token ');

    await user.click(screen.getByRole('button', { name: /Pipeline Başlat/i }));

    expect(onRun).toHaveBeenCalledTimes(1);
    expect(onRun.mock.calls[0]?.[0]).toMatchInlineSnapshot(`
      {
        "connectors": {
          "doorsNext": {
            "accessToken": "doors-token",
            "baseUrl": "https://doors.example.com",
            "password": "dng-pass",
            "projectArea": "DO-178C",
            "username": "dng",
          },
          "jama": {
            "baseUrl": "https://jama.example.com",
            "projectId": 123,
            "token": "jama-token",
          },
          "jenkins": {
            "baseUrl": "https://jenkins.example.com/",
            "build": 42,
            "job": "soipack-ci",
            "password": "password",
            "token": "jenkins-token",
            "username": "bob",
          },
          "polarion": {
            "baseUrl": "https://polarion.example.com",
            "password": "secret",
            "projectId": "AVIONICS",
            "token": "polarion-token",
            "username": "alice",
          },
        },
        "independentArtifacts": [],
        "independentSources": [],
      }
    `);
  });

  it('renders post-quantum signature metadata and fallbacks', () => {
    const { rerender } = render(<UploadAndRun {...createProps()} />);

    expect(screen.getByTestId('pack-signature-awaiting')).toBeInTheDocument();

    rerender(<UploadAndRun {...createProps({ packJobStatus: 'running' })} />);
    expect(screen.getByTestId('pack-signature-pending')).toBeInTheDocument();

    rerender(<UploadAndRun {...createProps({ packJobStatus: 'completed' })} />);
    expect(screen.getByTestId('pack-signature-missing')).toBeInTheDocument();

    rerender(
      <UploadAndRun
        {...createProps({
          packJobStatus: 'completed',
          postQuantumSignature: {
            algorithm: 'SPHINCS+',
            publicKey: 'BASE64KEY',
            signature: 'SIGNATURE',
          },
        })}
      />,
    );

    expect(screen.getByTestId('pack-signature-algorithm')).toHaveTextContent('SPHINCS+');
    expect(screen.getByTestId('pack-signature-public-key')).toHaveTextContent('BASE64KEY');
  });
});
