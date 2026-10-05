interface LeatherProvider {
  request(method: string, params?: unknown): Promise<any>;
}

interface Window {
  LeatherProvider?: LeatherProvider;
}
