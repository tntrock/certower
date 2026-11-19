import type { JSONSchema } from "../api";
import { useI18n } from "../i18n";

// SchemaForm renders a plugin's configuration schema as a form. Fields
// marked x-secret use password inputs; x-generated fields may be left
// empty for the server to fill. Optional nested objects get a toggle.

type Value = Record<string, unknown>;

export function SchemaForm({ schema, value, onChange, omit }: { schema: JSONSchema; value: Value; onChange: (v: Value) => void; omit?: string[] }) {
  const props = Object.fromEntries(Object.entries(schema.properties ?? {}).filter(([k]) => !omit?.includes(k)));
  return <ObjectFields schema={{ ...schema, properties: props }} value={value} onChange={onChange} path="" />;
}

function ObjectFields({ schema, value, onChange, path }: { schema: JSONSchema; value: Value; onChange: (v: Value) => void; path: string }) {
  const { t } = useI18n();
  const props = Object.entries(schema.properties ?? {});
  const required = new Set(schema.required ?? []);
  const set = (k: string, v: unknown) => {
    const next = { ...value };
    if (v === undefined || v === "") delete next[k];
    else next[k] = v;
    onChange(next);
  };

  return (
    <>
      {props.map(([key, prop]) => {
        const id = `f-${path}${key}`;
        const label = (prop.title ?? key) + (required.has(key) && !prop["x-generated"] ? " *" : "");
        if (prop.type === "object") {
          const enabled = value[key] !== undefined;
          return (
            <fieldset key={key}>
              <legend>
                <label className="check" style={{ margin: 0 }}>
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => set(key, e.target.checked ? {} : undefined)}
                  />
                  {prop.title ?? key}
                </label>
              </legend>
              {enabled && (
                <ObjectFields schema={prop} value={(value[key] as Value) ?? {}} onChange={(v) => set(key, v)} path={path + key + "."} />
              )}
            </fieldset>
          );
        }
        if (prop.type === "boolean") {
          return (
            <label className="check" key={key}>
              <input type="checkbox" checked={value[key] === true} onChange={(e) => set(key, e.target.checked || undefined)} />
              {label}
            </label>
          );
        }
        if (prop.type === "array") {
          const list = (value[key] as string[] | undefined) ?? [];
          return (
            <div className="field" key={key}>
              <label htmlFor={id}>{label}</label>
              <input
                id={id}
                value={list.join(", ")}
                onChange={(e) => {
                  const items = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                  set(key, items.length ? items : undefined);
                }}
              />
              <span className="hint">{t("Comma-separated")}</span>
            </div>
          );
        }
        if (prop.enum) {
          return (
            <div className="field" key={key}>
              <label htmlFor={id}>{label}</label>
              <select id={id} value={(value[key] as string | undefined) ?? ""} required={required.has(key)} onChange={(e) => set(key, e.target.value)}>
                {!required.has(key) && <option value="">{t("Default")}</option>}
                {prop.enum.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </div>
          );
        }
        const multiline = key.toLowerCase().includes("certificates") || key.toLowerCase().includes("pem");
        const common = {
          id,
          value: (value[key] as string | number | undefined) ?? "",
          required: required.has(key) && !prop["x-generated"],
          onChange: (e: { target: { value: string } }) =>
            set(key, prop.type === "integer" ? (e.target.value === "" ? undefined : Number(e.target.value)) : e.target.value),
        };
        return (
          <div className="field" key={key}>
            <label htmlFor={id}>{label}</label>
            {multiline ? (
              <textarea {...common} />
            ) : (
              <input
                {...common}
                type={prop["x-secret"] ? "password" : prop.type === "integer" ? "number" : prop.format === "email" ? "email" : "text"}
                autoComplete={prop["x-secret"] ? "new-password" : "off"}
                min={prop.minimum}
              />
            )}
            {prop["x-secret"] && <span className="hint">{t("Stored encrypted. It cannot be viewed again after saving.")}</span>}
            {prop["x-generated"] && <span className="hint">{t("Leave empty to have Certower generate it.")}</span>}
          </div>
        );
      })}
    </>
  );
}
