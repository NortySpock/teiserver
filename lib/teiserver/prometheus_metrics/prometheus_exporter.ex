defmodule Teiserver.PrometheusMetrics.PrometheusExporter do
  use Prometheus.PlugExporter

  def init(opts) do
    config = Application.get_env(:prometheus, __MODULE__, [])
    Keyword.merge(config, opts)
  end
end
