import { useState, useCallback } from 'react';

export function useActionState<TState, TRequest>(
  action: (prevState: TState, formData: TRequest) => Promise<TState>,
  initialState: TState
): [TState, (formData: TRequest) => Promise<void>, boolean] {
  const [state, setState] = useState<TState>(initialState);
  const [isLoading, setIsLoading] = useState(false);

  const formAction = useCallback(async (formData: TRequest) => {
    try {
      setIsLoading(true);
      const result = await action(state, formData);
      setState(result);
    } catch (error) {
      console.error('Action failed:', error);
    } finally {
      setIsLoading(false);
    }
  }, [action, state]);

  return [state, formAction, isLoading];
} 