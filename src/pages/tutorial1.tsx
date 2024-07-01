import { useEffect, useState } from 'react';

export default function Tutorial1() {
  const [result, setResult] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      const response = await fetch('/api/tutorial1');
      const data = await response.json();
      setResult(data);
    };
    fetchData().catch(console.error);
  }, []);

  return (
    <div>
      <h1>Running Tutorial1</h1>
      {result && (
        <pre>{JSON.stringify(result, null, 2)}</pre>
      )}
    </div>
  );
}
