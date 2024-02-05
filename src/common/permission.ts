import * as firestore from "../drivers/firestore";
import { auth } from "../drivers/firestore";
import { readLine } from "../util";
import { addDoc } from "firebase/firestore";

// TODO: Restructure permission-request table
// TODO: Use IDP data for principal
const submit = async <P>(type: string, permission: P) => {
  if (auth.currentUser === null || auth.tenantId === null)
    throw "not logged in";
  const uid = auth.currentUser?.uid;
  const tenantId = auth.tenantId;
  const now = Date.now() * 1e-3; // Permissions are in epoch seconds

  console.log(`Please enter a brief description of why you need access:`);
  process.stdout.write("$ ");
  const reason = await readLine();

  const data = {
    status: "NEW",
    requestedTimestamp: now,
    lastUpdatedTimestamp: now,
    uid,
    type,
    reason,
    permission,
  };
  const doc = await addDoc(
    firestore.collection(`o/${tenantId}/permission-events`),
    data
  );
  console.log(`Created request with ID ${doc.id}`);
  return doc.id;
};

export default { submit };
