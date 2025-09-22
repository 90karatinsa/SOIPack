export type PlanTemplateId = 'psac' | 'sdp' | 'svp' | 'scmp' | 'sqap';

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
