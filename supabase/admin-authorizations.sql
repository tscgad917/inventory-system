-- 總務課統一管理中心：管理人員授權名單
-- 請先在 Supabase SQL Editor 執行一次，再部署登入頁程式。
-- 本表只管理「哪些 email 可使用後台」；密碼仍由 Supabase Auth 個別保管。

create table if not exists public.admin_authorizations (
  email text primary key check (email = lower(trim(email))),
  role text not null default 'admin' check (role in ('owner', 'admin')),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  created_by text,
  updated_at timestamptz not null default now()
);

alter table public.admin_authorizations enable row level security;

grant select, insert, update, delete on public.admin_authorizations to authenticated;

-- 目前既有管理員保留唯一最高管理權限。
insert into public.admin_authorizations (email, role, is_active, created_by)
values ('tscgad917@gmail.com', 'owner', true, 'system')
on conflict (email) do update
set role = 'owner', is_active = true, updated_at = now();

drop policy if exists admin_authorizations_select_self_or_owner on public.admin_authorizations;
create policy admin_authorizations_select_self_or_owner
on public.admin_authorizations
for select
to authenticated
using (
  lower(coalesce(auth.jwt() ->> 'email', '')) = 'tscgad917@gmail.com'
  or (
    lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
    and is_active = true
  )
);

drop policy if exists admin_authorizations_owner_insert on public.admin_authorizations;
create policy admin_authorizations_owner_insert
on public.admin_authorizations
for insert
to authenticated
with check (
  lower(coalesce(auth.jwt() ->> 'email', '')) = 'tscgad917@gmail.com'
);

drop policy if exists admin_authorizations_owner_update on public.admin_authorizations;
create policy admin_authorizations_owner_update
on public.admin_authorizations
for update
to authenticated
using (
  lower(coalesce(auth.jwt() ->> 'email', '')) = 'tscgad917@gmail.com'
)
with check (
  lower(coalesce(auth.jwt() ->> 'email', '')) = 'tscgad917@gmail.com'
);

drop policy if exists admin_authorizations_owner_delete on public.admin_authorizations;
create policy admin_authorizations_owner_delete
on public.admin_authorizations
for delete
to authenticated
using (
  lower(coalesce(auth.jwt() ->> 'email', '')) = 'tscgad917@gmail.com'
);
