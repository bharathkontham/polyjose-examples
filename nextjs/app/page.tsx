// The page. It is a server component that renders text only; everything that calls polyjose is
// in the client component <Playground />, which runs it in the browser.
import Playground from "../components/Playground";

export default function Home() {
  return (
    <main>
      <h1>polyjose playground: browser and server</h1>
      <p>
        Sign, verify, encrypt and decrypt in this page with <code>@polyjose/wasm</code>, and send tokens to the route handlers
        under <code>/api</code>, which do the same on the server with <code>@polyjose/node</code>. Every tap logs each step; the
        Log tab can copy and share it, because it holds no secrets.
      </p>
      <p>
        Keys are software keys in page memory: polyjose 0.4.0 has no browser key store and no non-extractable WebCrypto keys.
        Every payload is a fixed demo text, and the RSA key is the published RFC 7515 Appendix A.2 test key.
      </p>
      <Playground />
    </main>
  );
}
