export default {
  async fetch(request, env) {
    return new Response("HarminPOS is live.", {
      headers: { "content-type": "text/plain" },
    });
  },
};