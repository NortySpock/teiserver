# ==============================================================================
# Cache Lock & Deadlock Risk Analyzer (`scripts/analyze_cache_locks.exs`)
# ==============================================================================
#
# Analyzes compiled BEAM files (`_build/<env>/lib/teiserver/ebin/Elixir.Teiserver*.beam`)
# to build a static function-level call graph and report ConCache lock hazards:
#
#   - Unique Lock Sites: Distinct lock-acquiring call sites reachable from a
#                        function (each downstream helper is expanded once).
#   - IO_UNDER_LOCK    : A `get_or_store` / `fetch_or_store` / `update` callback
#                        reaches `Teiserver.Repo` or `Ecto.Repo`.
#   - LOCK_UNDER_TX    : A `Repo.transaction` / `Repo.transact` callback reaches a
#                        ConCache lock.
#   - NESTED_LOCK      : A lock-holding callback reaches another ConCache lock.
#   - LOOP_LOCKS       : A lock-acquiring call occurs inside `Enum.each/map/reduce`
#                        or `Task.async_stream` (1..N locks per call).
#   - Exposure         : Static reachability from entry points (HIGH / MED / LOW).
#
# Example 1: Print top 25 riskiest functions + Mermaid diagrams for the top 3
#   mix compile
#   mix run --no-start scripts/analyze_cache_locks.exs
#
# Example 2: Verify the exact lock-site breakdown for a specific function
#   mix run --no-start scripts/analyze_cache_locks.exs \
#     --trace Teiserver.Account.UserCacheLib.recache_user/1
#
# Example 3: Generate a Mermaid `flowchart TD` for a specific function
#   mix run --no-start scripts/analyze_cache_locks.exs \
#     --mermaid Teiserver.Account.UserCacheLib.recache_user/1
# ==============================================================================

defmodule CacheLockAnalyzer do
  @moduledoc false

  # Treat both direct ConCache lock calls and CacheHelper/Teiserver lock wrappers
  # as leaf lock sinks so call-site multiplicity inside a function is preserved
  # without double-counting through wrappers.
  @lock_sinks MapSet.new([
                {ConCache, :put, 3},
                {ConCache, :delete, 2},
                {ConCache, :insert_new, 3},
                {ConCache, :update, 3},
                {ConCache, :get_or_store, 3},
                {ConCache, :fetch_or_store, 3},
                {ConCache, :isolated, 3},
                {ConCache, :isolated, 4},
                {Teiserver, :cache_get_or_store, 3},
                {Teiserver, :cache_delete, 2},
                {Teiserver, :cache_put, 3},
                {Teiserver, :cache_insert_new, 3},
                {Teiserver, :store_delete, 2},
                {Teiserver, :store_put, 3},
                {Teiserver, :store_insert_new, 3},
                {Teiserver, :store_update, 3},
                {Teiserver, :store_get_or_store, 3},
                {Teiserver.Helpers.CacheHelper, :cache_get_or_store, 3},
                {Teiserver.Helpers.CacheHelper, :cache_fetch_or_store, 3},
                {Teiserver.Helpers.CacheHelper, :cache_delete, 2},
                {Teiserver.Helpers.CacheHelper, :cache_put, 3},
                {Teiserver.Helpers.CacheHelper, :cache_insert_new, 3},
                {Teiserver.Helpers.CacheHelper, :cache_put_on_ok, 2},
                {Teiserver.Helpers.CacheHelper, :cache_put_on_ok, 3},
                {Teiserver.Helpers.CacheHelper, :cache_delete_on_ok, 2},
                {Teiserver.Helpers.CacheHelper, :cache_delete_on_ok, 3},
                {Teiserver.Helpers.CacheHelper, :store_delete, 2},
                {Teiserver.Helpers.CacheHelper, :store_put, 3},
                {Teiserver.Helpers.CacheHelper, :store_insert_new, 3},
                {Teiserver.Helpers.CacheHelper, :store_update, 3},
                {Teiserver.Helpers.CacheHelper, :store_get_or_store, 3}
              ])

  @lock_callback_callers MapSet.new([
                            {ConCache, :get_or_store, 3},
                            {ConCache, :fetch_or_store, 3},
                            {ConCache, :update, 3},
                            {Teiserver, :cache_get_or_store, 3},
                            {Teiserver, :store_get_or_store, 3},
                            {Teiserver, :store_update, 3},
                            {Teiserver.Helpers.CacheHelper, :cache_get_or_store, 3},
                            {Teiserver.Helpers.CacheHelper, :cache_fetch_or_store, 3},
                            {Teiserver.Helpers.CacheHelper, :store_get_or_store, 3},
                            {Teiserver.Helpers.CacheHelper, :store_update, 3}
                          ])

  @tx_callers MapSet.new([
                  {Teiserver.Repo, :transaction, 1},
                  {Teiserver.Repo, :transaction, 2},
                  {Teiserver.Repo, :transact, 1},
                  {Teiserver.Repo, :transact, 2}
                ])

  @loop_callers MapSet.new([
                    {Enum, :each, 2},
                    {Enum, :map, 2},
                    {Enum, :reduce, 3},
                    {Enum, :flat_map, 2},
                    {Task, :async_stream, 3},
                    {Task, :async_stream, 4}
                  ])

  @repo_mods MapSet.new([Teiserver.Repo, Ecto.Repo])

  @excluded_report_mods MapSet.new([
                          ConCache,
                          Teiserver,
                          Teiserver.Helpers.CacheHelper
                        ])

  def run(args) do
    {opts, _, _} =
      OptionParser.parse(args, switches: [mermaid: :string, trace: :string, top: :integer])

    top_n = opts[:top] || 25

    ebin_dir = Path.join([Mix.Project.build_path(), "lib", "teiserver", "ebin"])
    beam_files = Path.wildcard(Path.join(ebin_dir, "Elixir.Teiserver*.beam"))

    if beam_files == [] do
      Mix.raise("No .beam files found in #{ebin_dir}. Run `mix compile` first.")
    end

    parsed = Enum.flat_map(beam_files, &extract_module_calls/1)
    meta_map = Map.new(parsed)

    call_graph =
      Map.new(parsed, fn {mfa, info} ->
        {mfa, Map.keys(info.call_counts) |> MapSet.new()}
      end)

    reverse_graph = build_reverse_graph(call_graph)

    cond do
      opts[:trace] ->
        target = parse_mfa_string(opts[:trace])
        print_trace(target, meta_map)

      opts[:mermaid] ->
        target = parse_mfa_string(opts[:mermaid])
        IO.puts("### Mermaid Call Chain: `#{format_mfa(target)}`\n")
        IO.puts(emit_mermaid(target, call_graph, meta_map))

      true ->
        analyzed =
          Map.keys(call_graph)
          |> Enum.reject(fn {mod, _f, _a} -> MapSet.member?(@excluded_report_mods, mod) end)
          |> Enum.map(fn mfa ->
            {locks, loop_lock?} = count_locks(mfa, meta_map)
            info = Map.fetch!(meta_map, mfa)

            io_under_lock? = Enum.any?(info.lock_callbacks, &reaches_repo?(&1, call_graph))

            nested_lock? =
              Enum.any?(info.lock_callbacks, fn cb_mfa ->
                {cb_locks, _} = count_locks(cb_mfa, meta_map)
                cb_locks > 0
              end)

            lock_under_tx? =
              Enum.any?(info.tx_callbacks, fn tx_mfa ->
                {tx_locks, _} = count_locks(tx_mfa, meta_map)
                tx_locks > 0
              end)

            {exposure, entry_points} = classify_exposure(mfa, reverse_graph)

            hazards =
              []
              |> maybe_add(io_under_lock?, "IO_UNDER_LOCK")
              |> maybe_add(lock_under_tx?, "LOCK_UNDER_TX")
              |> maybe_add(nested_lock?, "NESTED_LOCK")
              |> maybe_add(loop_lock?, "LOOP_LOCKS")

            score = length(hazards) * 100 + locks * exposure_weight(exposure)

            %{
              mfa: mfa,
              locks: locks,
              hazards: hazards,
              exposure: exposure,
              entry_points: Enum.take(entry_points, 4),
              score: score
            }
          end)
          |> Enum.filter(fn r -> r.locks > 0 or r.hazards != [] end)
          |> Enum.sort_by(&{-&1.score, -&1.locks, inspect(&1.mfa)})

        print_markdown_table(Enum.take(analyzed, top_n))

        if analyzed != [] do
          IO.puts("\n### Mermaid Call Chains (Top 3 Hotspots)\n")

          analyzed
          |> Enum.take(3)
          |> Enum.each(fn item ->
            IO.puts("#### `#{format_mfa(item.mfa)}`\n")
            IO.puts(emit_mermaid(item.mfa, call_graph, meta_map))
            IO.puts("")
          end)
        end
    end
  end

  # --- BEAM Abstract Code Extraction ---

  defp extract_module_calls(beam_path) do
    beam_charlist = String.to_charlist(beam_path)

    case :beam_lib.chunks(beam_charlist, [:abstract_code]) do
      {:ok, {mod, [{:abstract_code, {:raw_abstract_v1, forms}}]}} ->
        for {:function, _line, fun, arity, clauses} <- forms do
          mfa = {mod, fun, arity}

          acc = %{
            call_counts: %{},
            loop_calls: MapSet.new(),
            lock_callbacks: [],
            tx_callbacks: [],
            lock_targets: []
          }

          acc = walk_forms(clauses, mod, false, acc)
          {mfa, acc}
        end

      _ ->
        []
    end
  end

  defp walk_forms(list, mod, in_loop?, acc) when is_list(list) do
    Enum.reduce(list, acc, &walk_forms(&1, mod, in_loop?, &2))
  end

  defp walk_forms(
         {:call, _line, {:remote, _l2, {:atom, _l3, target_mod}, {:atom, _l4, target_fun}}, args},
         mod,
         in_loop?,
         acc
       ) do
    target = {target_mod, target_fun, length(args)}
    acc = record_call(acc, target, in_loop?)
    acc = maybe_record_lock_target(acc, target, args)

    cond do
      MapSet.member?(@lock_callback_callers, target) ->
        cb = Enum.at(args, 2)
        {cb_calls, acc} = extract_callback_targets(cb, mod, acc)
        acc = %{acc | lock_callbacks: cb_calls ++ acc.lock_callbacks}
        walk_forms(Enum.take(args, 2), mod, in_loop?, acc)

      MapSet.member?(@tx_callers, target) ->
        cb = Enum.at(args, 0)
        {cb_calls, acc} = extract_callback_targets(cb, mod, acc)
        acc = %{acc | tx_callbacks: cb_calls ++ acc.tx_callbacks}
        walk_forms(Enum.drop(args, 1), mod, in_loop?, acc)

      MapSet.member?(@loop_callers, target) ->
        walk_forms(args, mod, true, acc)

      true ->
        walk_forms(args, mod, in_loop?, acc)
    end
  end

  defp walk_forms({:call, _line, {:atom, _l2, target_fun}, args}, mod, in_loop?, acc) do
    target = {mod, target_fun, length(args)}
    acc = record_call(acc, target, in_loop?)
    walk_forms(args, mod, in_loop?, acc)
  end

  defp walk_forms(
         {:fun, _line, {:function, {:atom, _, target_mod}, {:atom, _, target_fun}, {:integer, _, arity}}},
         _mod,
         in_loop?,
         acc
       ) do
    record_call(acc, {target_mod, target_fun, arity}, in_loop?)
  end

  defp walk_forms({:fun, _line, {:function, target_fun, arity}}, mod, in_loop?, acc)
       when is_atom(target_fun) and is_integer(arity) do
    record_call(acc, {mod, target_fun, arity}, in_loop?)
  end

  defp walk_forms(tuple, mod, in_loop?, acc) when is_tuple(tuple) do
    tuple
    |> Tuple.to_list()
    |> walk_forms(mod, in_loop?, acc)
  end

  defp walk_forms(_other, _mod, _in_loop?, acc), do: acc

  defp extract_callback_targets(nil, _mod, acc), do: {[], acc}

  defp extract_callback_targets(cb_ast, mod, acc) do
    sub_acc = %{
      call_counts: %{},
      loop_calls: MapSet.new(),
      lock_callbacks: [],
      tx_callbacks: [],
      lock_targets: []
    }

    sub_acc = walk_forms(cb_ast, mod, false, sub_acc)

    merged_counts =
      Map.merge(acc.call_counts, sub_acc.call_counts, fn _k, v1, v2 -> v1 + v2 end)

    merged = %{
      acc
      | call_counts: merged_counts,
        loop_calls: MapSet.union(acc.loop_calls, sub_acc.loop_calls),
        lock_callbacks: sub_acc.lock_callbacks ++ acc.lock_callbacks,
        tx_callbacks: sub_acc.tx_callbacks ++ acc.tx_callbacks,
        lock_targets: sub_acc.lock_targets ++ acc.lock_targets
    }

    {Map.keys(sub_acc.call_counts), merged}
  end

  defp maybe_record_lock_target(acc, target, args) do
    if MapSet.member?(@lock_sinks, target) do
      arg_idx =
        case target do
          {Teiserver.Helpers.CacheHelper, fun, _}
          when fun in [:cache_put_on_ok, :cache_delete_on_ok] ->
            1

          _ ->
            0
        end

      case format_lock_arg(Enum.at(args, arg_idx)) do
        nil -> acc
        label -> %{acc | lock_targets: [label | acc.lock_targets]}
      end
    else
      acc
    end
  end

  defp format_lock_arg({:atom, _line, atom}), do: inspect(atom)

  defp format_lock_arg({:var, _line, var}) when is_atom(var) do
    var
    |> Atom.to_string()
    |> String.replace(~r/^_/, "")
    |> String.replace(~r/@\d+$/, "")
  end

  defp format_lock_arg(_), do: nil

  defp record_call(acc, target, in_loop?) do
    counts = Map.update(acc.call_counts, target, 1, &(&1 + 1))
    acc = %{acc | call_counts: counts}
    if in_loop?, do: %{acc | loop_calls: MapSet.put(acc.loop_calls, target)}, else: acc
  end

  # --- DAG-Deduplicated Lock Counting ---

  defp count_locks(mfa, meta_map) do
    {count, loop?, _visited} = do_count_locks(mfa, meta_map, MapSet.new(), false)
    {count, loop?}
  end

  defp do_count_locks(mfa, meta_map, visited, in_loop?) do
    if MapSet.member?(visited, mfa) do
      {0, false, visited}
    else
      visited = MapSet.put(visited, mfa)

      case Map.get(meta_map, mfa) do
        nil ->
          {0, false, visited}

        info ->
          Enum.reduce(info.call_counts, {0, false, visited}, fn {callee, site_count},
                                                                {sum, loop_acc, vis} ->
            next_loop? = in_loop? or MapSet.member?(info.loop_calls, callee)

            if MapSet.member?(@lock_sinks, callee) do
              {sum + site_count, loop_acc or next_loop?, vis}
            else
              {c, l?, vis2} = do_count_locks(callee, meta_map, vis, next_loop?)
              {sum + c, loop_acc or l?, vis2}
            end
          end)
      end
    end
  end

  # --- Verification Trace ---

  defp print_trace(root_mfa, meta_map) do
    {total, loop?} = count_locks(root_mfa, meta_map)
    IO.puts("Trace for `#{format_mfa(root_mfa)}` (total unique lock sites: #{total}, loop?: #{loop?})\n")
    do_print_trace(root_mfa, meta_map, MapSet.new(), 0)
  end

  defp do_print_trace(mfa, meta_map, visited, depth) do
    indent = String.duplicate("  ", depth)
    visited = MapSet.put(visited, mfa)

    case Map.get(meta_map, mfa) do
      nil ->
        visited

      info ->
        Enum.reduce(info.call_counts, visited, fn {callee, site_count}, vis ->
          loop_tag = if MapSet.member?(info.loop_calls, callee), do: " [LOOP]", else: ""

          cond do
            MapSet.member?(@lock_sinks, callee) ->
              IO.puts("#{indent}- `#{format_mfa(callee)}` (x#{site_count}) [LOCK SINK]#{loop_tag}")
              vis

            MapSet.member?(vis, callee) ->
              vis

            true ->
              {sub_locks, _} = count_locks(callee, meta_map)

              if sub_locks > 0 do
                IO.puts("#{indent}- `#{format_mfa(callee)}` (#{sub_locks} lock sites)#{loop_tag}")
                do_print_trace(callee, meta_map, vis, depth + 1)
              else
                vis
              end
          end
        end)
    end
  end

  # --- Repo & Exposure Analysis ---

  defp reaches_repo?(mfa, call_graph) do
    do_reaches_repo?(mfa, call_graph, MapSet.new())
  end

  defp do_reaches_repo?({mod, _f, _a} = mfa, call_graph, visited) do
    cond do
      MapSet.member?(@repo_mods, mod) ->
        true

      MapSet.member?(visited, mfa) ->
        false

      true ->
        visited = MapSet.put(visited, mfa)

        call_graph
        |> Map.get(mfa, MapSet.new())
        |> Enum.any?(&do_reaches_repo?(&1, call_graph, visited))
    end
  end

  defp build_reverse_graph(call_graph) do
    Enum.reduce(call_graph, %{}, fn {caller, callees}, rev ->
      Enum.reduce(callees, rev, fn callee, acc ->
        Map.update(acc, callee, MapSet.new([caller]), &MapSet.put(&1, caller))
      end)
    end)
  end

  defp classify_exposure(mfa, reverse_graph) do
    ancestors = collect_ancestors(mfa, reverse_graph, MapSet.new([mfa]))

    entry_points =
      ancestors
      |> Enum.filter(fn anc -> tier_for_module(elem(anc, 0)) != nil end)
      |> Enum.map(&{tier_for_module(elem(&1, 0)), format_mfa(&1)})
      |> Enum.uniq()

    highest =
      cond do
        Enum.any?(entry_points, &(elem(&1, 0) == :high)) -> :high
        Enum.any?(entry_points, &(elem(&1, 0) == :med)) -> :med
        true -> :low
      end

    {highest, Enum.map(entry_points, &elem(&1, 1))}
  end

  defp collect_ancestors(mfa, reverse_graph, visited) do
    callers = Map.get(reverse_graph, mfa, MapSet.new())

    Enum.reduce(callers, visited, fn caller, acc ->
      if MapSet.member?(acc, caller) do
        acc
      else
        collect_ancestors(caller, reverse_graph, MapSet.put(acc, caller))
      end
    end)
  end

  defp tier_for_module(mod) do
    name = Atom.to_string(mod)

    cond do
      String.contains?(name, "SpringTcpServer") or
        String.contains?(name, "Tachyon") or
        String.contains?(name, "TeiserverWeb.") or
        String.contains?(name, "Teiserver.Client") or
        String.contains?(name, "Teiserver.Lobby") or
          String.contains?(name, "Teiserver.Battle") ->
        :high

      String.contains?(name, "Task") or
        String.contains?(name, "Bridge") or
        String.contains?(name, "Discord") or
          String.contains?(name, "Server") ->
        :med

      String.contains?(name, "Startup") or
          String.contains?(name, "Mix.Tasks") ->
        :low

      true ->
        nil
    end
  end

  defp exposure_weight(:high), do: 5
  defp exposure_weight(:med), do: 2
  defp exposure_weight(:low), do: 1

  # --- Output & Mermaid ---

  defp print_markdown_table(rows) do
    IO.puts("## Cache Lock Risk Report\n")
    IO.puts("| Function | Exposure | Unique Lock Sites | Hazards | Sample Entry Points |")
    IO.puts("|---|---|---:|---|---|")

    Enum.each(rows, fn r ->
      hazards_str = if r.hazards == [], do: "—", else: Enum.join(r.hazards, ", ")
      eps_str = if r.entry_points == [], do: "—", else: Enum.join(r.entry_points, "<br>")

      IO.puts(
        "| `#{format_mfa(r.mfa)}` | **#{String.upcase(to_string(r.exposure))}** | #{r.locks} | #{hazards_str} | #{eps_str} |"
      )
    end)
  end

  defp emit_mermaid(root_mfa, call_graph, meta_map) do
    {edges, nodes} = collect_lock_subgraph(root_mfa, call_graph, meta_map, MapSet.new())

    node_defs =
      nodes
      |> Enum.map(fn mfa ->
        id = node_id(mfa)
        {locks, _} = count_locks(mfa, meta_map)

        label =
          cond do
            MapSet.member?(@lock_sinks, mfa) ->
              "#{format_mfa(mfa)} [LOCK SINK]"

            locks == 1 ->
              case find_single_lock_target(mfa, meta_map) do
                nil -> "#{format_mfa(mfa)} [1 lock]"
                target -> "#{format_mfa(mfa)} [lock #{target}]"
              end

            locks > 0 ->
              "#{format_mfa(mfa)} [#{locks} locks]"

            true ->
              format_mfa(mfa)
          end

        "    #{id}[\"#{label}\"]"
      end)
      |> Enum.uniq()
      |> Enum.join("\n")

    edge_defs =
      edges
      |> Enum.map(fn {from, to} -> "    #{node_id(from)} --> #{node_id(to)}" end)
      |> Enum.uniq()
      |> Enum.join("\n")

    """
    ```mermaid
    flowchart TD
    #{node_defs}
    #{edge_defs}
    ```
    """
  end

  defp collect_lock_subgraph(mfa, call_graph, meta_map, visited) do
    if MapSet.member?(visited, mfa) or MapSet.member?(@lock_sinks, mfa) do
      {[], MapSet.new()}
    else
      visited = MapSet.put(visited, mfa)
      callees = Map.get(call_graph, mfa, MapSet.new())

      relevant_callees =
        Enum.filter(callees, fn c ->
          MapSet.member?(@lock_sinks, c) or elem(count_locks(c, meta_map), 0) > 0
        end)

      Enum.reduce(relevant_callees, {[], MapSet.new([mfa])}, fn callee, {e_acc, n_acc} ->
        {sub_e, sub_n} = collect_lock_subgraph(callee, call_graph, meta_map, visited)
        {[{mfa, callee} | sub_e] ++ e_acc, MapSet.put(MapSet.union(n_acc, sub_n), callee)}
      end)
    end
  end

  defp find_single_lock_target(mfa, meta_map) do
    {targets, _visited} = do_collect_lock_targets(mfa, meta_map, MapSet.new())

    case Enum.uniq(targets) do
      [single] -> single
      _ -> nil
    end
  end

  defp do_collect_lock_targets(mfa, meta_map, visited) do
    if MapSet.member?(visited, mfa) do
      {[], visited}
    else
      visited = MapSet.put(visited, mfa)

      case Map.get(meta_map, mfa) do
        nil ->
          {[], visited}

        info ->
          Enum.reduce(info.call_counts, {info.lock_targets, visited}, fn {callee, _},
                                                                        {acc, vis} ->
            if MapSet.member?(@lock_sinks, callee) do
              {acc, vis}
            else
              {sub, vis2} = do_collect_lock_targets(callee, meta_map, vis)
              {sub ++ acc, vis2}
            end
          end)
      end
    end
  end

  defp node_id(mfa), do: "N_" <> (:erlang.phash2(mfa) |> Integer.to_string(16))

  defp format_mfa({mod, fun, arity}) do
    short_mod = mod |> Atom.to_string() |> String.replace_prefix("Elixir.", "")
    "#{short_mod}.#{fun}/#{arity}"
  end

  defp parse_mfa_string(str) do
    [mod_fun, arity_str] = String.split(str, "/")
    parts = String.split(mod_fun, ".")
    {mod_parts, [fun_str]} = Enum.split(parts, length(parts) - 1)
    mod = String.to_existing_atom("Elixir." <> Enum.join(mod_parts, "."))
    fun = String.to_existing_atom(fun_str)
    {mod, fun, String.to_integer(arity_str)}
  end

  defp maybe_add(list, true, item), do: [item | list]
  defp maybe_add(list, false, _item), do: list
end

CacheLockAnalyzer.run(System.argv())
