// @ts-nocheck fixture: framework packages are not installed
import type { NextApiRequest, NextApiResponse } from 'next'

export default function post(req: NextApiRequest, res: NextApiResponse) {
  res.json({ id: req.query.postId })
}
