/** Generated model file */

private import javascript

private class Types extends ModelInput::TypeModelCsv {
  override predicate row(string row) {
    row =
      [
        "sqlite3.Database;sqlite3.Database;Member[addListener,all,each,exec,get,on,once,prependListener,prependOnceListener,run].ReturnValue", //
        "sqlite3.Database;sqlite3.DatabaseStatic;Instance", //
        "sqlite3.Database;sqlite3.Statement;Member[finalize].ReturnValue", //
        "sqlite3.Database;sqlite3;Member[cached].Member[Database].ReturnValue", //
        "sqlite3.DatabaseStatic;sqlite3.sqlite3;Member[Database]", //
        "sqlite3.DatabaseStatic;sqlite3;Member[Database]", //
        "sqlite3.RunResult;sqlite3.sqlite3;Member[RunResult]", //
        "sqlite3.Statement;sqlite3.Database;Member[prepare].ReturnValue", //
        "sqlite3.Statement;sqlite3.RunResult;", //
        "sqlite3.Statement;sqlite3.Statement;Member[all,bind,each,get,reset,run].ReturnValue", //
        "sqlite3.Statement;sqlite3.StatementStatic;Instance", //
        "sqlite3.StatementStatic;sqlite3.sqlite3;Member[Statement]", //
        "sqlite3.StatementStatic;sqlite3;Member[Statement]", //
        "sqlite3.sqlite3;sqlite3.sqlite3;Member[verbose].ReturnValue", //
        "sqlite3.sqlite3;sqlite3;Member[verbose].ReturnValue", //
      ]
  }
}

private class Summaries extends ModelInput::SummaryModelCsv {
  override predicate row(string row) {
    row =
      [
        "sqlite3.Database;;;Member[addListener,all,each,exec,get,on,once,prependListener,prependOnceListener,run].ReturnValue;type", //
        "sqlite3.Statement;;;Member[all,bind,each,get,reset,run].ReturnValue;type", //
        "sqlite3.sqlite3;;;Member[verbose].ReturnValue;type", //
      ]
  }
}
