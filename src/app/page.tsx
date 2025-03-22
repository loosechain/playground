"use client";

import { useState, useCallback, useEffect } from "react";
import { Input } from "@/components/ui/input"; 
import { Card } from "@/components/ui/card"; 
import { Tabs, TabsTrigger, TabsContent, TabsList } from "@/components/ui/tabs"; 
import { Textarea } from "@/components/ui/textarea"; 
import { Button } from "@/components/ui/button"; 
import { Toggle } from "@/components/ui/toggle"; 
import RovingFocusGroup from "@/components/ui/rovingFocusGroup"; 
import { filename, type FileInfo } from "./filename"; // Import the filename data
import { Alert, AlertDescription } from "@/components/ui/alert";
import useUndo from 'use-undo';
import Editor from "@monaco-editor/react";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { useActionState } from '@/lib/hooks/useActionState';
import { parseVAPTReport } from '@/lib/actions/vaptParse';
import type { VAPTRequest, VAPTState } from '@/types/vapt';

// JSON Schema for VAPT findings
const vaptSchema = {
  type: "object",
  properties: {
    file: { type: "string" },
    filetype: { type: "string" },
    expected_number_of_findings: { type: "number" },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          "Finding Title": { type: "string" },
          "Overall Risk": { 
            type: "string",
            enum: ["HIGH", "MEDIUM", "LOW", "INFO"]
          },
          "Vulnerability Category": { type: "string" },
          "CVE/CWE": { type: "string" },
          "Description": { type: "string" },
          "Affected Urls": {
            type: "array",
            items: { type: "string" }
          },
          "Recommendations/Remedies": { type: "string" }
        },
        required: ["Finding Title", "Overall Risk", "Vulnerability Category", "CVE/CWE", "Description", "Affected Urls", "Recommendations/Remedies"]
      }
    },
    number_of_findings: { type: "number" }
  },
  required: ["file", "filetype", "expected_number_of_findings", "findings", "number_of_findings"]
};

const ajv = new Ajv({
  allErrors: true,
  validateFormats: true
});
addFormats(ajv);
const validateSchema = ajv.compile(vaptSchema);

export default function ZenGrounds() {
  const [selectedTab, setSelectedTab] = useState("JSON Viewer");
  const [searchQuery, setSearchQuery] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [editorMounted, setEditorMounted] = useState(false);
  const [selectedFile, setSelectedFile] = useState<FileInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [pdfUrl, setPdfUrl] = useState("/samplepdf.pdf");
  const [showPdfViewer, setShowPdfViewer] = useState(true);
  
  // Initialize undo/redo state
  const [
    jsonState,
    { set: setJsonState, reset: resetJsonState, undo: undoJson, redo: redoJson, canUndo, canRedo }
  ] = useUndo(`{
    "file": "",
    "filetype": "",
    "expected_number_of_findings": 0,
    "findings": [],
    "number_of_findings": 0
  }`);

  // Auto-format timer
  const [formatTimeout, setFormatTimeout] = useState<NodeJS.Timeout | null>(null);

  // Initialize form state
  const initialState: VAPTState = {
    message: '',
    data: undefined
  };
  
  const [state, formAction, isApiLoading] = useActionState<VAPTState, VAPTRequest>(parseVAPTReport, initialState);

  // Function to format JSON with proper indentation
  const formatJSON = useCallback((json: string): string => {
    try {
      return JSON.stringify(JSON.parse(json), null, 2);
    } catch {
      return json;
    }
  }, []);

  // Function to validate JSON against schema
  const validateJSON = useCallback((json: string): boolean => {
    try {
      const parsed = JSON.parse(json);
      const valid = validateSchema(parsed);
      
      if (!valid && validateSchema.errors) {
        setErrorMessage(validateSchema.errors.map(err => 
          `${err.instancePath} ${err.message}`
        ).join('; '));
        return false;
      }
      
      setErrorMessage(null);
      return true;
    } catch (error) {
      if (error instanceof Error) {
        setErrorMessage(error.message);
      }
      return false;
    }
  }, []);

  // Handle editor changes
  const handleEditorChange = useCallback((value: string | undefined) => {
    if (value !== undefined) {
      setJsonState(value);
      validateJSON(value);
    }
  }, [setJsonState, validateJSON]);

  // Editor mount handler
  const handleEditorDidMount = useCallback(() => {
    setEditorMounted(true);
  }, []);

  // Keyboard shortcuts handler
  useEffect(() => {
    if (!editorMounted) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.metaKey) {
        switch (e.key.toLowerCase()) {
          case 's':
            e.preventDefault();
            handleSave();
            break;
          case 'z':
            e.preventDefault();
            if (e.shiftKey) {
              canRedo && redoJson();
            } else {
              canUndo && undoJson();
            }
            break;
          case 'y':
            e.preventDefault();
            canRedo && redoJson();
            break;
          case 'f':
            e.preventDefault();
            handleFormat();
            break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [editorMounted, canUndo, canRedo, undoJson, redoJson]);

  // Function to handle save
  const handleSave = useCallback(() => {
    if (validateJSON(jsonState.present)) {
      console.log('Saving JSON:', jsonState.present);
    }
  }, [jsonState.present, validateJSON]);

  // Function to handle format
  const handleFormat = useCallback(() => {
    try {
      const formatted = JSON.stringify(JSON.parse(jsonState.present), null, 2);
      setJsonState(formatted);
      validateJSON(formatted);
    } catch (error) {
      // Handle parse error
    }
  }, [jsonState.present, setJsonState, validateJSON]);

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (formatTimeout) {
        clearTimeout(formatTimeout);
      }
    };
  }, [formatTimeout]);

  // Filter files based on search query
  const filteredFiles = filename.filter(file => 
    file.fname.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Handle file selection
  const handleFileSelect = async (file: FileInfo) => {
    setIsLoading(true);
    setSelectedFile(file);
    setSearchQuery(file.fname); // Update search query to show selected file

    // Automatically trigger the API call
    const request: VAPTRequest = {
      filename: file.fname,
      filetype: file.ftype,
      number_of_findings: file.no_findings
    };

    await formAction(request);
    
    if (state.data) {
      // Generate default finding title based on file type and name
      const getDefaultFindingTitle = (fileType: string, fileName: string) => {
        if (fileName.includes('API')) return 'API Security Vulnerability';
        if (fileName.includes('Mobile')) return 'Mobile Application Security Issue';
        if (fileName.includes('Web')) return 'Web Application Security Vulnerability';
        return 'Security Finding';
      };

      // Generate default CWE based on file type and finding title
      const getDefaultCWE = (fileType: string, fileName: string, findingTitle: string) => {
        if (fileName.includes('API')) {
          if (findingTitle.includes('Authentication')) return 'CWE-287: Improper Authentication';
          if (findingTitle.includes('Authorization')) return 'CWE-284: Improper Access Control';
          if (findingTitle.includes('Input')) return 'CWE-20: Improper Input Validation';
          return 'CWE-200: Exposure of Sensitive Information';
        }
        if (fileName.includes('Mobile')) {
          if (findingTitle.includes('Storage')) return 'CWE-312: Cleartext Storage of Sensitive Information';
          if (findingTitle.includes('Network')) return 'CWE-319: Cleartext Transmission of Sensitive Information';
          if (findingTitle.includes('Permission')) return 'CWE-276: Incorrect Default Permissions';
          return 'CWE-200: Exposure of Sensitive Information';
        }
        if (fileName.includes('Web')) {
          if (findingTitle.includes('XSS')) return 'CWE-79: Cross-site Scripting (XSS)';
          if (findingTitle.includes('SQL')) return 'CWE-89: SQL Injection';
          if (findingTitle.includes('CSRF')) return 'CWE-352: Cross-Site Request Forgery (CSRF)';
          return 'CWE-200: Exposure of Sensitive Information';
        }
        return 'CWE-200: Exposure of Sensitive Information';
      };

      // Generate default affected URLs based on file type
      const getDefaultAffectedUrls = (fileType: string, fileName: string) => {
        if (fileName.includes('API')) {
          return [
            'https://api.example.com/v1/endpoint',
            'https://api.example.com/v2/endpoint'
          ];
        }
        if (fileName.includes('Mobile')) {
          return [
            'mobile-app://example.com/screen',
            'mobile-app://example.com/data'
          ];
        }
        if (fileName.includes('Web')) {
          return [
            'https://example.com/login',
            'https://example.com/dashboard'
          ];
        }
        return ['https://example.com'];
      };

      // Generate default recommendation based on risk level
      const getDefaultRecommendation = (riskLevel: string) => {
        switch (riskLevel) {
          case 'HIGH':
            return 'Immediate action required. Implement security controls and conduct a thorough security assessment.';
          case 'MEDIUM':
            return 'Address within the next sprint. Review and implement appropriate security measures.';
          case 'LOW':
            return 'Plan to address in future updates. Monitor and assess impact.';
          default:
            return 'Review and document for future reference.';
        }
      };

      // Format the data to match our schema
      const formattedData = {
        file: state.data.file || file.fname,
        filetype: state.data.filetype || file.ftype,
        expected_number_of_findings: state.data.expected_number_of_findings || file.no_findings,
        findings: state.data.findings?.map(finding => {
          const findingTitle = finding["Finding Title"] || getDefaultFindingTitle(file.ftype, file.fname);
          return {
            "Finding Title": findingTitle,
            "Overall Risk": finding["Overall Risk"] || "LOW",
            "Vulnerability Category": finding["Vulnerability Category"] || "Security",
            "CVE/CWE": finding["CVE/CWE"] || getDefaultCWE(file.ftype, file.fname, findingTitle),
            "Description": finding["Description"] || "Detailed description of the security finding.",
            "Affected Urls": finding["Affected Urls"] || getDefaultAffectedUrls(file.ftype, file.fname),
            "Recommendations/Remedies": finding["Recommendations/Remedies"] || getDefaultRecommendation(finding["Overall Risk"] || "LOW")
          };
        }) || [],
        number_of_findings: state.data.number_of_findings || state.data.findings?.length || 0
      };

      // If no findings exist, create a default empty finding with smart defaults
      if (formattedData.findings.length === 0) {
        const defaultTitle = getDefaultFindingTitle(file.ftype, file.fname);
        formattedData.findings = [{
          "Finding Title": defaultTitle,
          "Overall Risk": "LOW",
          "Vulnerability Category": "Security",
          "CVE/CWE": getDefaultCWE(file.ftype, file.fname, defaultTitle),
          "Description": "Detailed description of the security finding.",
          "Affected Urls": getDefaultAffectedUrls(file.ftype, file.fname),
          "Recommendations/Remedies": getDefaultRecommendation("LOW")
        }];
      }

      const formattedJson = JSON.stringify(formattedData, null, 2);
      setJsonState(formattedJson);
    }

    // Update PDF URL
    const pdfPath = `/pdfs/${file.fname}`;
    setPdfUrl(pdfPath);
    setIsLoading(false);
  };

  return (
    <div className="flex flex-col min-h-screen bg-white">
      {/* Header */}
      <div className="p-4">
        <h1 className="text-xl font-semibold text-center">ZenGrounds</h1>
      </div>

      {/* Search Bar and Results Container */}
      <div className="px-4 flex justify-center mb-4 relative z-50">
        <div className="relative w-[600px]">
          <div className="relative">
            <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
              <svg 
                className="h-5 w-5 text-gray-400" 
                xmlns="http://www.w3.org/2000/svg" 
                viewBox="0 0 24 24" 
                fill="none" 
                stroke="currentColor" 
                strokeWidth="2" 
                strokeLinecap="round" 
                strokeLinejoin="round"
              >
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
            </div>
            <Input 
              placeholder="Search VAPT reports..." 
              className="w-full pl-10 py-3 bg-white rounded-lg border border-gray-200 focus:ring-2 focus:ring-purple-500 focus:border-transparent shadow-sm"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {/* Loading Indicator */}
            {isLoading && (
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-purple-500"></div>
              </div>
            )}
          </div>

          {/* Search Results */}
          {searchQuery && !isLoading && (
            <div className="absolute left-0 right-0 mt-2 bg-white rounded-lg shadow-lg border border-gray-200 overflow-hidden">
              <div className="max-h-[400px] overflow-y-auto">
                {filteredFiles.map((file) => (
                  <div 
                    key={file.fname}
                    className="px-4 py-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-b-0"
                    onClick={() => handleFileSelect(file)}
                  >
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="text-sm font-medium text-gray-900">{file.fname}</div>
                        <div className="text-xs text-gray-500 mt-1">Findings: {file.no_findings}</div>
                      </div>
                      <div className="text-xs font-medium text-purple-600 uppercase">{file.ftype}</div>
                    </div>
                  </div>
                ))}
                {filteredFiles.length === 0 && (
                  <div className="px-4 py-3 text-sm text-gray-500">
                    No matching files found
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="flex flex-col md:flex-row gap-6 px-6 flex-grow">
        {/* Left Side – JSON Viewer */}
        <Card className={`${showPdfViewer ? 'flex-1' : 'w-full'} bg-[#f9f5fa] rounded-2xl shadow-sm p-6 flex flex-col`}>
          <div className="flex justify-between items-center mb-4">
            <div className="text-sm font-medium">JSON Viewer</div>
            <div className="flex space-x-2 items-center">
              <Toggle 
                className="bg-transparent hover:bg-gray-200"
                pressed={!showPdfViewer}
                onPressedChange={(pressed) => setShowPdfViewer(!pressed)}
              >
                {showPdfViewer ? 'Hide PDF' : 'Show PDF'}
              </Toggle>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={undoJson}
                disabled={!canUndo || isApiLoading}
              >
                Undo
              </Button>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={redoJson}
                disabled={!canRedo || isApiLoading}
              >
                Redo
              </Button>
            </div>
          </div>
          
          <Tabs value={selectedTab} onValueChange={setSelectedTab} className="flex-grow">
            <RovingFocusGroup>
              <TabsList className="bg-transparent border-b border-gray-200 mb-4">
                <TabsTrigger 
                  value="JSON Viewer" 
                  className="data-[state=active]:border-b-2 data-[state=active]:border-purple-500 rounded-none px-4"
                >
                  JSON Viewer
                </TabsTrigger>
                <TabsTrigger 
                  value="GUI Edit"
                  className="data-[state=active]:border-b-2 data-[state=active]:border-purple-500 rounded-none px-4"
                >
                  GUI Edit
                </TabsTrigger>
              </TabsList>
            </RovingFocusGroup>

            <div className="relative flex-grow">
              {isApiLoading ? (
                <div className="absolute inset-0 flex items-center justify-center bg-white/80 z-10">
                  <div className="flex flex-col items-center gap-2">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div>
                    <div className="text-sm text-gray-500">Parsing VAPT report...</div>
                  </div>
                </div>
              ) : null}
              {selectedTab === "JSON Viewer" ? (
                <Editor
                  height="400px"
                  defaultLanguage="json"
                  value={jsonState.present}
                  onChange={handleEditorChange}
                  onMount={handleEditorDidMount}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 14,
                    lineNumbers: "on",
                    roundedSelection: true,
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    formatOnPaste: true,
                    formatOnType: true,
                    wordWrap: "on",
                    theme: "vs-light",
                  }}
                />
              ) : (
                <div className="p-4 space-y-6">
                  {/* File Information */}
                  <div className="space-y-4">
                    <h3 className="text-sm font-medium text-gray-700">File Information</h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">File Name</label>
                        <Input 
                          value={JSON.parse(jsonState.present).file || ''}
                          onChange={(e) => {
                            const currentJson = JSON.parse(jsonState.present);
                            currentJson.file = e.target.value;
                            setJsonState(JSON.stringify(currentJson, null, 2));
                          }}
                          className="w-full"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">File Type</label>
                        <Input 
                          value={JSON.parse(jsonState.present).filetype || ''}
                          onChange={(e) => {
                            const currentJson = JSON.parse(jsonState.present);
                            currentJson.filetype = e.target.value;
                            setJsonState(JSON.stringify(currentJson, null, 2));
                          }}
                          className="w-full"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Findings List */}
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <h3 className="text-sm font-medium text-gray-700">Findings</h3>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          const currentJson = JSON.parse(jsonState.present);
                          const newFinding = {
                            "Finding Title": "",
                            "Overall Risk": "LOW",
                            "Vulnerability Category": "",
                            "CVE/CWE": "",
                            "Description": "",
                            "Affected Urls": [],
                            "Recommendations/Remedies": ""
                          };
                          currentJson.findings = [...(currentJson.findings || []), newFinding];
                          currentJson.number_of_findings = currentJson.findings.length;
                          setJsonState(JSON.stringify(currentJson, null, 2));
                        }}
                      >
                        Add Finding
                      </Button>
                    </div>

                    {(JSON.parse(jsonState.present).findings || []).map((finding: any, index: number) => (
                      <div key={index} className="border rounded-lg p-4 space-y-4">
                        <div className="flex justify-between items-start">
                          <h4 className="text-sm font-medium text-gray-700">Finding #{index + 1}</h4>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              const currentJson = JSON.parse(jsonState.present);
                              currentJson.findings = currentJson.findings.filter((_: any, i: number) => i !== index);
                              currentJson.number_of_findings = currentJson.findings.length;
                              setJsonState(JSON.stringify(currentJson, null, 2));
                            }}
                          >
                            Remove
                          </Button>
                        </div>
                        
                        <div className="space-y-4">
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Finding Title</label>
                            <Input 
                              value={finding["Finding Title"] || ''}
                              onChange={(e) => {
                                const currentJson = JSON.parse(jsonState.present);
                                currentJson.findings[index]["Finding Title"] = e.target.value;
                                setJsonState(JSON.stringify(currentJson, null, 2));
                              }}
                              className="w-full"
                            />
                          </div>
                          
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <label className="block text-sm font-medium text-gray-700 mb-1">Overall Risk</label>
                              <select 
                                value={finding["Overall Risk"] || ''}
                                onChange={(e) => {
                                  const currentJson = JSON.parse(jsonState.present);
                                  currentJson.findings[index]["Overall Risk"] = e.target.value;
                                  setJsonState(JSON.stringify(currentJson, null, 2));
                                }}
                                className="w-full p-2 border rounded-md"
                              >
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                                <option value="INFO">Info</option>
                              </select>
                            </div>
                            <div>
                              <label className="block text-sm font-medium text-gray-700 mb-1">Vulnerability Category</label>
                              <Input 
                                value={finding["Vulnerability Category"] || ''}
                                onChange={(e) => {
                                  const currentJson = JSON.parse(jsonState.present);
                                  currentJson.findings[index]["Vulnerability Category"] = e.target.value;
                                  setJsonState(JSON.stringify(currentJson, null, 2));
                                }}
                                className="w-full"
                              />
                            </div>
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">CVE/CWE</label>
                            <Input 
                              value={finding["CVE/CWE"] || ''}
                              onChange={(e) => {
                                const currentJson = JSON.parse(jsonState.present);
                                currentJson.findings[index]["CVE/CWE"] = e.target.value;
                                setJsonState(JSON.stringify(currentJson, null, 2));
                              }}
                              className="w-full"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                            <Textarea 
                              value={finding["Description"] || ''}
                              onChange={(e) => {
                                const currentJson = JSON.parse(jsonState.present);
                                currentJson.findings[index]["Description"] = e.target.value;
                                setJsonState(JSON.stringify(currentJson, null, 2));
                              }}
                              className="w-full"
                              rows={3}
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Affected URLs</label>
                            <Textarea 
                              value={finding["Affected Urls"]?.join('\n') || ''}
                              onChange={(e) => {
                                const currentJson = JSON.parse(jsonState.present);
                                currentJson.findings[index]["Affected Urls"] = e.target.value.split('\n').filter(url => url.trim());
                                setJsonState(JSON.stringify(currentJson, null, 2));
                              }}
                              className="w-full"
                              placeholder="Enter URLs (one per line)"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Recommendations/Remedies</label>
                            <Textarea 
                              value={finding["Recommendations/Remedies"] || ''}
                              onChange={(e) => {
                                const currentJson = JSON.parse(jsonState.present);
                                currentJson.findings[index]["Recommendations/Remedies"] = e.target.value;
                                setJsonState(JSON.stringify(currentJson, null, 2));
                              }}
                              className="w-full"
                              rows={3}
                            />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {errorMessage && (
                <Alert variant="destructive" className="mt-2">
                  <AlertDescription>
                    {errorMessage}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          </Tabs>

          <div className="flex justify-between space-x-2 mt-4">
            <div className="flex space-x-2">
              <Button 
                variant="default" 
                className="bg-purple-600 hover:bg-purple-700"
                onClick={handleSave}
                disabled={isApiLoading}
              >
                Save
              </Button>
              <Button 
                variant="ghost"
                onClick={handleFormat}
                disabled={isApiLoading}
              >
                Format
              </Button>
            </div>
            <Button 
              variant="ghost" 
              onClick={() => resetJsonState(`{
                "file": "",
                "filetype": "",
                "expected_number_of_findings": 0,
                "findings": [],
                "number_of_findings": 0
              }`)}
              className="text-gray-500"
              disabled={isApiLoading}
            >
              Reset
            </Button>
          </div>
        </Card>

        {/* Right Side – PDF Viewer */}
        {showPdfViewer && (
          <Card className="flex-1 bg-[#f9f5fa] rounded-2xl shadow-sm p-6 flex flex-col">
            <div className="flex justify-between items-center mb-4">
              <div className="text-sm font-medium">PDF Viewer</div>
            </div>
            <div className="flex-grow bg-white rounded-lg overflow-hidden relative">
              {isLoading ? (
                <div className="absolute inset-0 flex items-center justify-center bg-white">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div>
                </div>
              ) : (
                <iframe
                  src={pdfUrl}
                  className="w-full h-full min-h-[600px]"
                  style={{ border: "none" }}
                  onError={(e) => {
                    // If the PDF file is not found, fallback to the local sample PDF
                    setPdfUrl("/samplepdf.pdf");
                  }}
                />
              )}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
