import { useRef, useState } from "react";
import jsQR from "jsqr";
import { QrCode, Upload, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";

export function QrScanner({ onDecoded }: { onDecoded: (url: string) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decoded, setDecoded] = useState<string | null>(null);

  async function handleFile(file: File) {
    setBusy(true);
    setError(null);
    setDecoded(null);
    try {
      const bitmap = await createImageBitmap(file);
      const canvas = document.createElement("canvas");
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("Canvas unavailable in this browser.");
      ctx.drawImage(bitmap, 0, 0);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(data.data, data.width, data.height, { inversionAttempts: "attemptBoth" });
      if (!code?.data) throw new Error("No QR code found in that image. Try a sharper, closer crop.");
      const text = code.data.trim();
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text) && !/^[\w-]+(\.[\w-]+)+/.test(text)) {
        throw new Error(`QR decoded, but it is not a URL: "${text.slice(0, 60)}"`);
      }
      setDecoded(text);
      onDecoded(text);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read that QR code.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-4 rounded-2xl border border-border bg-card/60 p-4 backdrop-blur">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 text-sm">
          <QrCode className="h-4 w-4 text-primary" />
          <span className="font-medium">QR code scanner</span>
          <span className="text-xs text-muted-foreground">Upload a QR image to extract and scan its link</span>
        </div>
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          disabled={busy}
          className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-border bg-background/40 px-3 py-1.5 text-xs font-medium text-foreground/85 transition hover:border-primary/40 hover:text-primary disabled:opacity-60"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
          {busy ? "Decoding…" : "Upload QR image"}
        </button>
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void handleFile(f);
            e.target.value = "";
          }}
        />
      </div>
      {decoded && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-success/40 bg-success/10 p-2.5 text-xs text-success">
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span className="break-all font-mono">{decoded}</span>
        </div>
      )}
      {error && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/10 p-2.5 text-xs text-destructive">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
