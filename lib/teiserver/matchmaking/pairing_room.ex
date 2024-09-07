defmodule Teiserver.Matchmaking.PairingRoom do
  @moduledoc """
  This module handles all the interactions between players that have been
  matched for a game.
  It is responsible to kick off the start of the match when everyone is
  ready.
  """

  # Use a temporary restart strategy. Because there is no real way to recover
  # from a crash, the important transient state would be lost.
  use GenServer, restart: :temporary

  # import Teiserver.Matchmaking.QueueServer, only:
  alias Teiserver.Matchmaking.QueueServer
  alias Teiserver.Data.Types, as: T

  @timeout_ms 20_000

  @type team :: [QueueServer.member()]

  @spec start(QueueServer.id(), QueueServer.queue(), [team()]) :: {:ok, pid()} | {:error, term()}
  def start(queue_id, queue, teams) do
    GenServer.start(__MODULE__, {queue_id, queue, teams})
  end

  @type state :: %{
          queue_id: QueueServer.id(),
          queue: QueueServer.queue(),
          teams: [QueueServer.member()],
          awaiting: [T.userid()]
        }

  @impl true
  def init({queue_id, queue, teams}) do
    initial_state =
      %{
        queue_id: queue_id,
        queue: queue,
        teams: teams,
        awaiting:
          Enum.flat_map(teams, fn team ->
            Enum.flat_map(team, fn member -> member.player_ids end)
          end)
      }

    {:ok, initial_state, {:continue, :notify_players}}
  end

  @impl true
  def handle_continue(:notify_players, state) do
    Enum.each(state.awaiting, fn player_id ->
      Teiserver.Player.notify_found(player_id, state.queue_id, @timeout_ms)
    end)

    {:noreply, state}
  end
end
