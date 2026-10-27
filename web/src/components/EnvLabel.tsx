export function EnvLabel({ label, color }: { label: string | null; color: string | null }) {
  if (!label) return null;
  const tint = color ?? "#a1a1aa";
  return (
    <span className="env-pill" style={{ color: tint, background: `color-mix(in srgb, ${tint} 12%, transparent)` }}>
      {label}
    </span>
  );
}
