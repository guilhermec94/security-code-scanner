# Security Code Scanner

## Techstack

| Tool                                                                                  | Usage                                        |
|:--------------------------------------------------------------------------------------|:---------------------------------------------|
| [GoLang](https://go.dev/)                                                             | Build this tool                              |
| [Cobra](https://github.com/spf13/cobra)                                               | Create cli commands                          |
| [Logrus](https://github.com/sirupsen/logrus)                                          | Have structured logs                         |

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
    - Currently comments are also catched in the validations, applying this approach of a AST would allow to filter them out from the validation