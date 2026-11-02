-- 庫存盤點期間：自動開放／手動提前開放／手動關閉
-- 請先在 Supabase SQL Editor 執行本檔，再部署 period.html 與 index.html。

ALTER TABLE public.inventory_periods
ADD COLUMN IF NOT EXISTS open_mode text;

-- 舊資料轉換：原本 is_open=true 視為管理人員已手動開放；
-- 原本 is_open=false 改為自動模式，避免未來盤點日仍被舊狀態阻擋。
UPDATE public.inventory_periods
SET open_mode = CASE
  WHEN is_open IS TRUE THEN 'open'
  ELSE 'auto'
END
WHERE open_mode IS NULL;

ALTER TABLE public.inventory_periods
ALTER COLUMN open_mode SET DEFAULT 'auto',
ALTER COLUMN open_mode SET NOT NULL;

ALTER TABLE public.inventory_periods
DROP CONSTRAINT IF EXISTS inventory_periods_open_mode_check;

ALTER TABLE public.inventory_periods
ADD CONSTRAINT inventory_periods_open_mode_check
CHECK (open_mode IN ('auto', 'open', 'closed'));

CREATE OR REPLACE FUNCTION public.enforce_inventory_period_open_mode()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_open_mode text;
  v_taipei_today date := (now() AT TIME ZONE 'Asia/Taipei')::date;
BEGIN
  SELECT p.open_mode
    INTO v_open_mode
  FROM public.inventory_periods AS p
  WHERE p.count_date = NEW.count_date
  ORDER BY p.period_month DESC
  LIMIT 1
  FOR SHARE;

  IF v_open_mode IS NULL THEN
    RAISE EXCEPTION '目前沒有符合本次盤點日期的盤點期間設定。';
  END IF;

  IF v_open_mode = 'closed' THEN
    RAISE EXCEPTION '管理人員已手動關閉本次盤點，暫不接受資料。';
  END IF;

  IF v_open_mode = 'auto' AND NEW.count_date <> v_taipei_today THEN
    RAISE EXCEPTION '自動開放模式僅限實際盤點日當天送出。';
  END IF;

  IF v_open_mode = 'open' AND NEW.count_date < v_taipei_today THEN
    RAISE EXCEPTION '本次盤點日期已過，無法再送出資料。';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforce_inventory_period_open_mode
ON public.monthly_counts;

CREATE TRIGGER trg_enforce_inventory_period_open_mode
BEFORE INSERT OR UPDATE OF count_date
ON public.monthly_counts
FOR EACH ROW
EXECUTE FUNCTION public.enforce_inventory_period_open_mode();
