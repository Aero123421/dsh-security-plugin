// @ts-nocheck fixture: framework packages are not installed
async function handler(request: Request) {
  return new Response('ok')
}

export { handler as GET, handler as POST }
