# harkonnen

Harkonnen is a powerful CLI tool for parsing and analyzing HAR (HTTP Archive) files.

## Installation

```
go install github.com/yourusername/harkonnen@latest
```

## Usage

```
harkonnen har [flags] <input-files...>
```

## Examples

### Basic usage: Display all requests

```
harkonnen har example.har
```

### Filter requests by URL pattern

```
harkonnen har --match-urls="^https://api\.example\.com" example.har
```

### Show only request headers

```
harkonnen har --with-request --with-request-headers --with-response=false example.har
```

### Display specific request headers

```
harkonnen har --request-headers=Content-Type,Authorization example.har
```

### Show request bodies

```
harkonnen har --with-request-body example.har
```

### Decode JSON request bodies

```
harkonnen har --with-request-body --decode-request-json example.har
```

### Display response data with specific headers

```
harkonnen har --with-response --response-headers=Content-Type,Set-Cookie example.har
```

### Show response bodies

```
harkonnen har --with-response-body example.har
```

### Decode JSON response bodies

```
harkonnen har --with-response-body --decode-response-json example.har
```

### Output as JSON

```
harkonnen har --output=json example.har
```

### Filter and sort output

```
harkonnen har --fields=request.url,response.status --sort-by=response.status example.har
```

### Process multiple HAR files

```
harkonnen har file1.har file2.har file3.har
```

## Advanced Usage

### Custom output template

```
harkonnen har --output=template --template="{{.request.method}} {{.request.url}}: {{.response.status}}" example.har
```

### Export to SQLite

```
harkonnen har --output=sqlite --output-file=requests.db example.har
```

### Stream large HAR files

```
harkonnen har --stream large_file.har
```

## Notes

- Use `harkonnen har --help` for a full list of options
- Combine flags for powerful filtering and output customization
