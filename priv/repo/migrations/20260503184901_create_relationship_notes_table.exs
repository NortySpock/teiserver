defmodule Teiserver.Repo.Migrations.CreateRelationshipNotesTable do
  use Ecto.Migration

  def change do
    create table(:relationship_notes, primary_key: false) do
      add :from_user_id, references(:account_users, on_delete: :nothing), primary_key: true
      add :to_user_id, references(:account_users, on_delete: :nothing), primary_key: true
      add :note, :text, null: false

      add :inserted_at, :utc_datetime, null: false, default: fragment("now()")
      add :updated_at, :utc_datetime, null: false, default: fragment("now()")
    end
  end
end
