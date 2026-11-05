import type { ReactNode } from "react";
import { Empty } from "./ui";

export interface Column<T> { key: string; header: string; render: (row: T) => ReactNode; className?: string; }

export function DataTable<T>({ columns, rows, keyFn, empty = "No records." }: {
  columns: Column<T>[]; rows: T[]; keyFn: (r: T) => string | number; empty?: string;
}) {
  if (rows.length === 0) return <Empty>{empty}</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead><tr>{columns.map((c) => <th key={c.key} className="th">{c.header}</th>)}</tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={keyFn(r)} className="hover:bg-bg-soft/60">
              {columns.map((c) => <td key={c.key} className={`td ${c.className ?? ""}`}>{c.render(r)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
