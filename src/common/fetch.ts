/** Converts object data to a URL encoded form */
export const urlEncode = (data: Record<string, string>) =>
  Object.entries(data)
    .map((kv) => kv.map(encodeURIComponent).join("="))
    .join("&");

/** Validates an HTTP response, throwing a friendly
 *  error message if invalid
 */
export const validateResponse = async (response: Response) => {
  if (response.ok) return;
  throw new Error(`Error in fetch request to ${response.url.split("?")[0]}:
${response.status} ${response.statusText}

${await response.text()}`);
};
