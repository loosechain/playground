'use server'

import { z } from 'zod';
import { VAPTRequest, VAPTResponse, VAPTState } from '@/types/vapt';

// Validation schema
const vaptRequestSchema = z.object({
  filename: z.string().min(1, "Filename is required"),
  filetype: z.string().min(1, "File type is required"),
  number_of_findings: z.number().min(0, "Number of findings must be non-negative")
});

export async function parseVAPTReport(
  prevState: VAPTState,
  formData: VAPTRequest
): Promise<VAPTState> {
  try {
    // Validate the input
    const validatedFields = vaptRequestSchema.safeParse(formData);

    if (!validatedFields.success) {
      return {
        message: validatedFields.error.errors[0].message,
        data: undefined
      };
    }

    // Make the request to your FastAPI server
    const queryParams = new URLSearchParams({
      filename: formData.filename,
      filetype: formData.filetype,
      number_of_findings: formData.number_of_findings.toString()
    });

    const response = await fetch(
      `http://127.0.0.1:8000/parse?${queryParams}`,
      {
        method: 'POST',
        headers: {
          'accept': 'application/json',
        },
        cache: 'no-store'
      }
    );

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return { message: 'Success', data };

  } catch (error) {
    return {
      message: error instanceof Error ? error.message : 'Failed to parse VAPT report',
      data: undefined
    };
  }
}
