declare module 'xlsx-populate' {
  interface Cell {
    value(val?: any): any;
    style(style: any): Cell;
  }
  interface Row {
    cell(index: number | string): Cell;
    style(style: any): Row;
  }
  interface Column {
    width(w: number): Column;
    hidden(h?: boolean): boolean | Column;
  }
  interface Sheet {
    name(name?: string): string | Sheet;
    cell(address: string): Cell;
    row(index: number): Row;
    column(index: number | string): Column;
  }
  interface Workbook {
    sheet(index: number | string): Sheet;
    sheets(): Sheet[];
    addSheet(name: string): Sheet;
    outputAsync(options?: { password?: string; type?: string }): Promise<Buffer>;
    toFileAsync(filePath: string, options?: { password?: string }): Promise<void>;
  }
  const XlsxPopulate: {
    fromBlankAsync(): Promise<Workbook>;
    fromDataAsync(data: any, options?: { password?: string }): Promise<Workbook>;
    fromFileAsync(filePath: string, options?: { password?: string }): Promise<Workbook>;
  };
  export default XlsxPopulate;
}
