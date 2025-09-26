export type PlanTemplateId = 'psac' | 'sdp' | 'svp' | 'scmp' | 'sqap' | 'do330-ta';

export interface PlanSectionDefinition {
  id: string;
  title: string;
}

export interface PlanTemplateDefinition {
  id: PlanTemplateId;
  title: string;
  purpose: string;
  sections: PlanSectionDefinition[];
}
