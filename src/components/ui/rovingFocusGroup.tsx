// src/components/ui/rovingFocusGroup.tsx
import * as React from "react";

const RovingFocusGroup: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div role="group" tabIndex={0}>
      {children}
    </div>
  );
};

export default RovingFocusGroup;