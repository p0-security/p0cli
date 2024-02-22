import { getDoc } from "firebase/firestore";

export const mockGetDoc = (data: any) =>
  (getDoc as jest.Mock).mockResolvedValue({ data: () => data });
