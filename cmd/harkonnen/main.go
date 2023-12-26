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

var _ cmds.GlazeCommand = (*HARCommand)(nil)

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
				parameters.NewParameterDefinition(
					"decode-request-json",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Decode request body as JSON"),
					parameters.WithDefault(false),
				),
				parameters.NewParameterDefinition(
					"decode-response-json",
					parameters.ParameterTypeBool,
					parameters.WithHelp("Decode response body as JSON"),
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

type HARSettings struct {
	InputFiles          []string `glazed.parameter:"input-files"`
	RequestHeaders      []string `glazed.parameter:"request-headers"`
	WithRequestHeaders  bool     `glazed.parameter:"with-request-headers"`
	ResponseHeaders     []string `glazed.parameter:"response-headers"`
	WithResponseHeaders bool     `glazed.parameter:"with-response-headers"`
	RequestCookies      []string `glazed.parameter:"request-cookies"`
	WithRequestCookies  bool     `glazed.parameter:"with-request-cookies"`
	ResponseCookies     []string `glazed.parameter:"response-cookies"`
	WithResponseCookies bool     `glazed.parameter:"with-response-cookies"`
	MatchURLs           []string `glazed.parameter:"match-urls"`
	WithRequest         bool     `glazed.parameter:"with-request"`
	WithResponse        bool     `glazed.parameter:"with-response"`
	WithRequestBody     bool     `glazed.parameter:"with-request-body"`
	WithResponseBody    bool     `glazed.parameter:"with-response-body"`
	DecodeRequestJSON   bool     `glazed.parameter:"decode-request-json"`
	DecodeResponseJSON  bool     `glazed.parameter:"decode-response-json"`
}

func (h *HARCommand) RunIntoGlazeProcessor(
	ctx context.Context,
	parsedLayers *layers.ParsedLayers,
	gp middlewares.Processor,
) error {
	s := &HARSettings{}
	err := parsedLayers.InitializeStruct(layers.DefaultSlug, s)
	if err != nil {
		return err
	}

	if s.WithRequestBody && !s.WithRequest {
		s.WithRequest = true
	}
	if s.WithResponseBody && !s.WithResponse {
		s.WithResponse = true
	}

	for _, inputFile := range s.InputFiles {
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
			if entry.Request != nil && s.WithRequest {
				if len(s.MatchURLs) > 0 {
					matched := false
					for _, matchURL := range s.MatchURLs {
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
				if request.PostData != nil {
					if s.DecodeRequestJSON {
						var data interface{}
						if err := json.Unmarshal([]byte(request.PostData.Text), &data); err == nil {
							row.Set("request.postData", data)
						} else {
							row.Set("request.postData", request.PostData.Text)
						}
					} else {
						row.Set("request.postData", request.PostData.Text)
					}

					if len(request.PostData.Params) > 0 {
						params := map[string]string{}
						for _, param := range request.PostData.Params {
							params[param.Name] = param.Value
						}
						row.Set("request.postData.params", params)
					}
				}

				if s.WithRequestCookies {
					if len(s.RequestCookies) > 0 {
						cookies := map[string]string{}
						for _, cookie := range request.Cookies {
							for _, requestCookie := range s.RequestCookies {
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

				if s.WithRequestHeaders {
					if len(s.RequestHeaders) > 0 {
						headers := map[string]string{}
						for _, header := range request.Headers {
							for _, requestHeader := range s.RequestHeaders {
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

				if s.WithRequestBody {
					if request.PostData != nil {
						if s.DecodeRequestJSON {
							var v interface{}
							if err := json.Unmarshal([]byte(request.PostData.Text), &v); err == nil {
								row.Set("request.body", v)
							} else {
								row.Set("request.body", request.PostData.Text)
							}
						} else {
							row.Set("request.body", request.PostData.Text)
						}
					}
				}
			}

			if entry.Response != nil && s.WithResponse {
				response := entry.Response
				row.Set("response.status", response.Status)
				if response.StatusText != "" {
					row.Set("response.statusText", response.StatusText)
				}

				if s.WithResponseCookies {
					if len(s.ResponseCookies) > 0 {
						cookies := map[string]string{}
						for _, cookie := range response.Cookies {
							for _, responseCookie := range s.ResponseCookies {
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
				if s.WithResponseHeaders {
					if len(s.ResponseHeaders) > 0 {
						headers := map[string]string{}
						for _, header := range response.Headers {
							for _, responseHeader := range s.ResponseHeaders {
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

				if response.Content != nil && s.WithResponseBody {
					content := response.Content
					row.Set("response.content.mimeType", content.MimeType)
					if s.DecodeResponseJSON {
						var v interface{}
						if err := json.Unmarshal([]byte(content.Text), &v); err == nil {
							row.Set("response.content.text", v)
						} else {
							row.Set("response.content.text", content.Text)
						}
					} else {
						row.Set("response.content.text", content.Text)
					}
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
