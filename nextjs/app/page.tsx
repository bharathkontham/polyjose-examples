// The page. It is a server component that renders text only; everything that calls polyjose is
// in the client component <Playground />, which runs it in the browser.
import Playground from "../components/Playground";

export default function Home() {
  return (
    <main>
      <h1>polyjose: browser and server</h1>
      <p>
        The browser signs, verifies, encrypts and decrypts with <code>@polyjose/wasm</code>. The route handlers under{" "}
        <code>/api</code> do the same on the server with <code>@polyjose/node</code>. Each button sends one token across and
        logs both sides&apos; steps.
      </p>
      <p>
        Keys are software keys in memory: polyjose 0.4.0 has no browser key store and no non-extractable WebCrypto keys.
        Every message is a fixed demo text.
      </p>
      <Playground />
    </main>
  );
}
