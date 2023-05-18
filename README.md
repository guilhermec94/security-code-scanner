# Security Code Scanner

## Tech stack
- [GoLang](https://go.dev/) 
- [Cobra](https://github.com/spf13/cobra) 
- [Logrus](https://github.com/sirupsen/logrus)

## How to

In order to run the scanner you need to provide 3 arguments in the following order

- --source (path for the source code to scan)
- --output (path to output the results)
- --output-format (output format (text or json))

This tool can be executed using go

`go run main.go scanner ./output ./path/to/source/code text`

Or using the compiled executable file which can be obtained by running the command `go build`

`./security-code-scanner scanner ./output ./path/to/source/code text`

## Improvements

- In order for this tool to be able to perform a more rigorous analysis, one improvement would be to convert all source code from any language to a common model to be analyzed
  - It would need a parser implementation for each language to obtain a AST (Abstract Syntax Tree) for example
- Scan configuration could be served as a config file which would allow to define other settings such as for example, set the number of workers for each type of security validation. 