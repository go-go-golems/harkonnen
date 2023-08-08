package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/chromedp/cdproto/har"
	"github.com/go-go-golems/glazed/pkg/cli"
	"github.com/go-go-golems/glazed/pkg/cmds"
	"github.com/go-go-golems/glazed/pkg/cmds/layers"
	"github.com/go-go-golems/glazed/pkg/cmds/parameters"
	"github.com/go-go-golems/glazed/pkg/help"
	"github.com/go-go-golems/glazed/pkg/middlewares"
	"github.com/go-go-golems/glazed/pkg/settings"
	"github.com/go-go-golems/glazed/pkg/types"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"os"
	"regexp"
)

type HARCommand struct {
	*cmds.CommandDescription
}

func NewHARCommand() (*HARCommand, error) {
	glazedParameterLayer, err := settings.NewGlazedParameterLayers()
	if err != nil {
		return nil, err
	}

	return &HARCommand{
		CommandDescription: cmds.NewCommandDescription(
			"har",
			cmds.WithShort("Format HAR data"),
			cmds.WithFlags(
				parameters.NewParameterDefinition(
					"request-headers",
					parameters.ParameterTypeStringList,
					parameters.WithHelp("Request headers to include"),
					parameters.WithDefault([]string{}),
				),
				parameters.NewParameterDefinition(
					"with-request-headers",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include request headers"),
					parameters.WithDefault(true),
				),
				parameters.NewParameterDefinition(
					"response-headers",
					parameters.ParameterTypeStringList,
					parameters.WithHelp("Response headers to include"),
					parameters.WithDefault([]string{}),
				),
				parameters.NewParameterDefinition(
					"with-response-headers",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include response headers"),
					parameters.WithDefault(true),
				),

				parameters.NewParameterDefinition(
					"request-cookies",
					parameters.ParameterTypeStringList,
					parameters.WithHelp("Request cookies to include"),
					parameters.WithDefault([]string{}),
				),
				parameters.NewParameterDefinition(
					"with-request-cookies",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include request cookies"),
					parameters.WithDefault(false),
				),

				parameters.NewParameterDefinition(
					"response-cookies",
					parameters.ParameterTypeStringList,
					parameters.WithHelp("Response cookies to include"),
					parameters.WithDefault([]string{}),
				),
				parameters.NewParameterDefinition(
					"with-response-cookies",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include response cookies"),
					parameters.WithDefault(false),
				),

				parameters.NewParameterDefinition(
					"match-urls",
					parameters.ParameterTypeStringList,
					parameters.WithHelp("URLs to include (regexp)"),
					parameters.WithDefault([]string{}),
				),

				parameters.NewParameterDefinition(
					"with-request",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include request data"),
					parameters.WithDefault(true),
				),
				parameters.NewParameterDefinition(
					"with-response",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include response data"),
					parameters.WithDefault(false),
				),

				parameters.NewParameterDefinition(
					"with-request-body",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include request body"),
					parameters.WithDefault(false),
				),
				parameters.NewParameterDefinition(
					"with-response-body",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Include response body"),
					parameters.WithDefault(false),
				),
			),
			cmds.WithArguments(
				parameters.NewParameterDefinition(
					"input-files",
					parameters.ParameterTypeStringList,
					parameters.WithRequired(true),
				),
			),
			cmds.WithLayers(
				glazedParameterLayer,
			),
		),
	}, nil
}

func (h *HARCommand) Run(
	ctx context.Context,
	parsedLayers map[string]*layers.ParsedParameterLayer,
	ps map[string]interface{},
	gp middlewares.Processor,
) error {
	inputFiles, ok := ps["input-files"].([]string)
	if !ok {
		return fmt.Errorf("input-files argument is not a string list")
	}

	requestHeaders := ps["request-headers"].([]string)
	withRequestHeaders := ps["with-request-headers"].(bool)
	responseHeaders := ps["response-headers"].([]string)
	withResponseHeaders := ps["with-response-headers"].(bool)
	requestCookies := ps["request-cookies"].([]string)
	withRequestCookies := ps["with-request-cookies"].(bool)
	responseCookies := ps["response-cookies"].([]string)
	withResponseCookies := ps["with-response-cookies"].(bool)
	matchURLs := ps["match-urls"].([]string)
	withRequest := ps["with-request"].(bool)
	withResponse := ps["with-response"].(bool)
	withRequestBody := ps["with-request-body"].(bool)
	withResponseBody := ps["with-response-body"].(bool)

	for _, inputFile := range inputFiles {
		f, err := os.Open(inputFile)
		if err != nil {
			return errors.Wrapf(err, "could not open input file %s", inputFile)
		}
		defer func(f *os.File) {
			_ = f.Close()
		}(f)

		var har har.HAR
		if err := json.NewDecoder(f).Decode(&har); err != nil {
			return errors.Wrapf(err, "could not decode input file %s", inputFile)
		}

		if har.Log == nil {
			return fmt.Errorf("could not find log in HAR file %s", inputFile)
		}
		log := har.Log

		for _, entry := range log.Entries {
			row := types.NewRow()
			if entry.Request != nil && withRequest {
				if len(matchURLs) > 0 {
					matched := false
					for _, matchURL := range matchURLs {
						if matched, _ = regexp.MatchString(matchURL, entry.Request.URL); matched {
							break
						}
					}
					if !matched {
						continue
					}
				}

				request := entry.Request
				row.Set("request.method", request.Method)
				row.Set("request.url", request.URL)

				if withRequestCookies {
					if len(requestCookies) > 0 {
						cookies := map[string]string{}
						for _, cookie := range request.Cookies {
							for _, requestCookie := range requestCookies {
								if cookie.Name == requestCookie {
									cookies[cookie.Name] = cookie.Value
								}
							}
						}
						row.Set("request.cookies", cookies)
					} else {
						row.Set("request.cookies", request.Cookies)
					}
				}

				if withRequestHeaders {
					if len(requestHeaders) > 0 {
						headers := map[string]string{}
						for _, header := range request.Headers {
							for _, requestHeader := range requestHeaders {
								if header.Name == requestHeader {
									headers[header.Name] = header.Value
								}
							}
						}
						row.Set("request.headers", headers)
					} else {
						headers := map[string]string{}
						for _, header := range request.Headers {
							if header.Name == "Cookie" || header.Name == "cookie" {
								continue
							}
							headers[header.Name] = header.Value
						}
						row.Set("request.headers", headers)
					}
				}

				if len(request.QueryString) > 0 {
					v := map[string]string{}
					for _, param := range request.QueryString {
						v[param.Name] = param.Value
					}
					row.Set("request.queryString", v)
				}

				if withRequestBody {
					if request.PostData != nil {
						row.Set("request.body", request.PostData.Text)
					}
				}
			}

			if entry.Response != nil && withResponse {
				response := entry.Response
				row.Set("response.status", response.Status)
				if response.StatusText != "" {
					row.Set("response.statusText", response.StatusText)
				}

				if withResponseCookies {
					if len(responseCookies) > 0 {
						cookies := map[string]string{}
						for _, cookie := range response.Cookies {
							for _, responseCookie := range responseCookies {
								if cookie.Name == responseCookie {
									cookies[cookie.Name] = cookie.Value
								}
							}
						}
						row.Set("response.cookies", cookies)
					} else {
						row.Set("response.cookies", response.Cookies)
					}
				}
				if withResponseHeaders {
					if len(responseHeaders) > 0 {
						headers := map[string]string{}
						for _, header := range response.Headers {
							for _, responseHeader := range responseHeaders {
								if header.Name == responseHeader {
									headers[header.Name] = header.Value
								}
							}
						}
						row.Set("response.headers", headers)
					} else {
						headers := map[string]string{}
						for _, header := range response.Headers {
							if header.Name == "cookie" || header.Name == "Cookie" {
								continue
							}
							headers[header.Name] = header.Value
						}
						row.Set("response.headers", headers)
					}
				}

				if response.RedirectURL != "" {
					row.Set("response.redirectURL", response.RedirectURL)
				}

				if response.Content != nil && withResponseBody {
					content := response.Content
					row.Set("response.content.mimeType", content.MimeType)
					row.Set("response.content.text", content.Text)
				}
			}

			err = gp.AddRow(ctx, row)
			if err != nil {
				return errors.Wrap(err, "could not process input object")
			}
		}
	}

	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "harkonnen",
		Short: "Harkonnen is a tool for processing HAR files",
	}

	helpSystem := help.NewHelpSystem()
	//err := helpSystem.LoadSectionsFromFS(docFS, ".")
	//cobra.CheckErr(err)

	helpSystem.SetupCobraRootCommand(rootCmd)

	cmd, err := NewHARCommand()
	if err != nil {
		panic(err)
	}

	cobraCommand, err := cli.BuildCobraCommandFromGlazeCommand(cmd)
	if err != nil {
		panic(err)
	}

	rootCmd.AddCommand(cobraCommand)

	_, err = rootCmd.ExecuteC()
	cobra.CheckErr(err)
}
