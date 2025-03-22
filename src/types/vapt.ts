export type FileType = "PDF" | "vapt" | "xlsx";

export interface FileInfo {
  fname: string;
  ftype: FileType;
  no_findings: number;
}

export interface VAPTRequest {
  filename: string;
  filetype: string;
  number_of_findings: number;
}

export interface Finding {
  "Finding Title": string;
  "Overall Risk": "HIGH" | "MEDIUM" | "LOW" | "INFO";
  "Vulnerability Category": string;
  "CVE/CWE": string;
  "Description": string;
  "Affected Urls": string[];
  "Recommendations/Remedies": string;
}

export interface VAPTResponse {
  file: string;
  filetype: string;
  expected_number_of_findings: number;
  findings: Finding[];
  number_of_findings: number;
}

export interface VAPTState {
  message: string;
  data?: VAPTResponse;
}
