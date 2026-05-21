defmodule TeiserverWeb.Live.PartyTest do
  use TeiserverWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  alias Teiserver.Helpers.GeneralTestLib
  alias Teiserver.TeiserverTestLib

  setup do
    TeiserverTestLib.player_permissions()
    |> GeneralTestLib.conn_setup()
    |> TeiserverTestLib.conn_setup()
  end

  describe "party live" do
    test "index", %{conn: conn} do
      {:ok, view, html} = live(conn, "/teiserver/account/parties")

      assert view != nil
      assert html =~ "Connect with client to enable"
      assert html =~ "Parties"
    end
  end
end
