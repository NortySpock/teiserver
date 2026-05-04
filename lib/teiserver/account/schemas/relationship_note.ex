defmodule Teiserver.Account.RelationshipNote do
  @moduledoc false
  use TeiserverWeb, :schema

  @primary_key false
  typed_schema "relationship_notes" do
    belongs_to :from_user, Teiserver.Account.User, primary_key: true
    belongs_to :to_user, Teiserver.Account.User, primary_key: true

    field :note, :string

    field :inserted_at, :utc_datetime
    field :updated_at, :utc_datetime
  end

  @doc """
  Builds a changeset based on the `struct` and `params`.
  """
  @spec changeset(map(), map()) :: Ecto.Changeset.t()
  def changeset(struct, params \\ %{}) do
    params =
      params
      |> trim_strings(~w(note)a)

    struct
    |> cast(params, ~w(from_user_id to_user_id note)a)
    |> validate_required(~w(from_user_id to_user_id note)a)
    |> validate_length(:note, max: 1000)
  end

  @spec authorize(atom(), Plug.Conn.t(), map()) :: bool()
  def authorize(:index, conn, _data), do: allow?(conn, "Moderator")
end
