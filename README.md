# Security Code Scanner

## Techstack
- Golang
- Cobra for setting up console commands
- Logrus for structured logs

## How to
In order to run the scanner you need to provide 3 arguments in the following order
- path for the output results
- path for the source code to scan
- output format (text or json)

This tool can be executed using go

```go run main.go scanner ./output ./path/to/source/code text```

Or using the compiled binary file

```./security-code-scanner scanner ./output ./path/to/source/code text```


## Improvements
- Convert source code from any language to a commun model to be analyzed
    - Would need a parser for each language to obtain a AST (Abstract Syntax Tree, for example)