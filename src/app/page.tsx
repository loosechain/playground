"use client";

import { useState, useCallback, useEffect } from "react";
import { Input } from "@/components/ui/input"; 
import { Card } from "@/components/ui/card"; 
import { Tabs, TabsTrigger, TabsContent, TabsList } from "@/components/ui/tabs"; 
import { Textarea } from "@/components/ui/textarea"; 
import { Button } from "@/components/ui/button"; 
import { Toggle } from "@/components/ui/toggle"; 
import RovingFocusGroup from "@/components/ui/rovingFocusGroup"; 
import { filename } from "./filename"; // Import the filename data
import { Alert, AlertDescription } from "@/components/ui/alert";
import useUndo from 'use-undo';
import Editor from "@monaco-editor/react";
import Ajv from "ajv";
import addFormats from "ajv-formats";

// JSON Schema for VAPT findings
const vaptSchema = {
  type: "object",
  properties: {
    finding_title: { type: "string" },
    "CVE/CWE": { type: "string" },
    Risk: { 
      type: "string",
      enum: ["High", "Medium", "Low", "Info"]
    },
    Affected_URLs: {
      type: "array",
      items: { 
        type: "string",
        pattern: "^https?://[\\w-]+(\\.[\\w-]+)+([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?$"
      }
    },
    "Recommendation/Remedies": {
      type: "array",
      items: { type: "string" }
    }
  },
  required: ["finding_title", "CVE/CWE", "Risk", "Affected_URLs"]
};

const ajv = new Ajv({
  allErrors: true,
  validateFormats: true
});
addFormats(ajv);
const validateSchema = ajv.compile(vaptSchema);

export default function ZenGrounds() {
  const [selectedTab, setSelectedTab] = useState("Gemma 3");
  const [searchQuery, setSearchQuery] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [editorMounted, setEditorMounted] = useState(false);
  
  // Initialize undo/redo state
  const [
    jsonState,
    { set: setJsonState, reset: resetJsonState, undo: undoJson, redo: redoJson, canUndo, canRedo }
  ] = useUndo(`{
    "finding_title": "SQL Injection Vulnerability in Login Page",
    "CVE/CWE": "CWE-89",
    "Risk": "High",
    "Affected_URLs": [
      "https://example.com/login",
      "https://example.com/user-data"
    ],
    "Recommendation/Remedies": []
  }`);

  // Auto-format timer
  const [formatTimeout, setFormatTimeout] = useState<NodeJS.Timeout | null>(null);

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

  return (
    <div className="flex flex-col min-h-screen bg-white">
      {/* Header */}
      <div className="p-4">
        <h1 className="text-xl font-semibold text-center">ZenGrounds</h1>
      </div>

      {/* Search Bar and Results Container */}
      <div className="px-4 flex justify-center mb-4 relative z-50">
        <div className="relative w-96">
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
            placeholder="search reports" 
            className="w-full pl-10 py-2 bg-gray-100 rounded-full border-none focus:ring-2 focus:ring-purple-500"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />

          {/* Search Results - Now absolutely positioned */}
          {searchQuery && (
            <div className="absolute left-0 right-0 mt-2 max-h-60 overflow-y-auto bg-white rounded-lg shadow-lg border">
              {filteredFiles.map((file, index) => (
                <div 
                  key={file.fname}
                  className="px-4 py-2 hover:bg-gray-50 cursor-pointer flex justify-between items-center"
                  onClick={() => {
                    // Here you can handle file selection
                    console.log('Selected file:', file);
                  }}
                >
                  <div className="flex-1">
                    <div className="text-sm font-medium">{file.fname}</div>
                    <div className="text-xs text-gray-500">Findings: {file.no_findings}</div>
                  </div>
                  <div className="text-xs text-gray-400 uppercase">{file.ftype}</div>
                </div>
              ))}
              {filteredFiles.length === 0 && (
                <div className="px-4 py-2 text-sm text-gray-500">
                  No matching files found
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="flex flex-col md:flex-row gap-6 px-6 flex-grow">
        {/* Left Side – JSON Viewer */}
        <Card className="flex-1 bg-[#f9f5fa] rounded-2xl shadow-sm p-6 flex flex-col">
          <div className="flex justify-between items-center mb-4">
            <div className="text-sm font-medium">JSON Viewer</div>
            <div className="flex space-x-2">
              <Button 
                variant="ghost" 
                size="sm"
                onClick={undoJson}
                disabled={!canUndo}
              >
                Undo
              </Button>
              <Button 
                variant="ghost" 
                size="sm"
                onClick={redoJson}
                disabled={!canRedo}
              >
                Redo
              </Button>
            </div>
          </div>
          
          <Tabs value={selectedTab} onValueChange={setSelectedTab} className="flex-grow">
            <RovingFocusGroup>
              <TabsList className="bg-transparent border-b border-gray-200 mb-4">
                <TabsTrigger 
                  value="Gemma 3" 
                  className="data-[state=active]:border-b-2 data-[state=active]:border-purple-500 rounded-none px-4"
                >
                  Gemma 3
                </TabsTrigger>
                <TabsTrigger 
                  value="Llama 3.2"
                  className="data-[state=active]:border-b-2 data-[state=active]:border-purple-500 rounded-none px-4"
                >
                  Llama 3.2
                </TabsTrigger>
                <TabsTrigger 
                  value="Phi 3.5"
                  className="data-[state=active]:border-b-2 data-[state=active]:border-purple-500 rounded-none px-4"
                >
                  Phi 3.5
                </TabsTrigger>
                <TabsTrigger 
                  value="Llama 3.3 (API)"
                  className="data-[state=active]:border-b-2 data-[state=active]:border-purple-500 rounded-none px-4"
                >
                  Llama 3.3 (API)
                </TabsTrigger>
              </TabsList>
            </RovingFocusGroup>

            <div className="relative flex-grow">
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
              >
                Save
              </Button>
              <Button 
                variant="ghost"
                onClick={handleFormat}
              >
                Format
              </Button>
            </div>
            <Button 
              variant="ghost" 
              onClick={() => resetJsonState()}
              className="text-gray-500"
            >
              Reset
            </Button>
          </div>
        </Card>

        {/* Right Side – PDF Viewer */}
        <Card className="flex-1 bg-[#f9f5fa] rounded-2xl shadow-sm p-6 flex flex-col">
          <div className="flex justify-between items-center mb-4">
            <div className="text-sm font-medium">PDF Viewer</div>
            <Toggle className="bg-transparent hover:bg-gray-200">Toggle View</Toggle>
          </div>
          <div className="flex-grow bg-white rounded-lg overflow-hidden">
            <iframe
              src="https://sample-files.com/downloads/documents/pdf/basic-text.pdf"
              className="w-full h-full min-h-[600px]"
              style={{ border: "none" }}
            />
          </div>
        </Card>
      </div>
    </div>
  );
}
