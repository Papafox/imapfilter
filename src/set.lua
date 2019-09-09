-- A simple implementation of sets.

Set = {}

Set._mt = {}
setmetatable(Set, Set._mt)


function Set._new(self, values)
    local object

    object = values or {}

    object._type = 'set'

    for key, value in pairs(Set) do
        if type(value) == 'function' then object[key] = value end
    end

    object._mt = {}
    object._mt.__add = object._union
    object._mt.__mul = object._intersection
    object._mt.__sub = object._difference
    setmetatable(object, object._mt)

    return object
end

function Set._union(seta, setb)
    local set = Set()
    local t = {}

    for _, v in ipairs(seta) do
        b, m = table.unpack(v)
        if not t[b] then t[b] = {} end
        t[b][m] = true
    end
    for _, v in ipairs(setb) do
        b, m = table.unpack(v)
        if not t[b] then t[b] = {} end
        t[b][m] = true
    end
    for b in pairs(t) do
        for m in pairs(t[b]) do table.insert(set, { b, m }) end
    end

    return set
end

function Set._intersection(seta, setb)
    local set = Set()
    local ta = {}
    local tb = {}

    for _, v in ipairs(seta) do
        b, m = table.unpack(v)
        if not ta[b] then ta[b] = {} end
        ta[b][m] = true
    end
    for _, v in ipairs(setb) do
        b, m = table.unpack(v)
        if not tb[b] then tb[b] = {} end
        tb[b][m] = true
    end
    for b in pairs(ta) do
        if tb[b] then
            for m in pairs(ta[b]) do
                if tb[b][m] then table.insert(set, { b, m }) end
            end
        end
    end

    return set
end

function Set._difference(seta, setb)
    local set = Set()
    local t = {}

    for _, v in ipairs(seta) do
        b, m = table.unpack(v)
        if not t[b] then t[b] = {} end
        t[b][m] = true
    end
    for _, v in ipairs(setb) do
        b, m = table.unpack(v)
        if t[b] then t[b][m] = nil end
    end
    for b in pairs(t) do
        for m in pairs(t[b]) do table.insert(set, { b, m }) end
    end

    return set
end


function Set.add_flags(self, flags)
    _check_required(flags, 'table')

    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.add_flags(mbox, flags, self) then r = false end
    end
    return r
end

function Set.remove_flags(self, flags)
    _check_required(flags, 'table')

    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.remove_flags(mbox, flags, self) then r = false end
    end
    return r
end

function Set.replace_flags(self, flags)
    _check_required(flags, 'table')

    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.replace_flags(mbox, flags, self) then r = false end
    end
    return r
end

function Set.mark_answered(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.mark_answered(mbox, self) then r = false end
    end
    return r
end

function Set.mark_deleted(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.mark_deleted(mbox, self) then r = false end
    end
    return r
end

function Set.mark_draft(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.mark_draft(mbox, self) then r = false end
    end
    return r
end

function Set.mark_flagged(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.mark_flagged(mbox, self) then r = false end
    end
    return r
end

function Set.mark_seen(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.mark_seen(mbox, self) then r = false end
    end
    return r
end

function Set.unmark_answered(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.unmark_answered(mbox, self) then r = false end
    end
    return r
end

function Set.unmark_deleted(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.unmark_deleted(mbox, self) then r = false end
    end
    return r
end

function Set.unmark_draft(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.unmark_draft(mbox, self) then r = false end
    end
    return r
end

function Set.unmark_flagged(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.unmark_flagged(mbox, self) then r = false end
    end
    return r
end

function Set.unmark_seen(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.unmark_seen(mbox, self) then r = false end
    end
    return r
end

function Set.delete_messages(self)
    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.delete_messages(mbox, self) then r = false end
    end
    return r
end

function Set.copy_messages(self, dest)
    _check_required(dest, 'table')

    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.copy_messages(mbox, dest, self) then r = false end
    end
    return r
end

function Set.move_messages(self, dest)
    _check_required(dest, 'table')

    local r = true
    for mbox in pairs(_extract_mailboxes(self)) do
        if not mbox.move_messages(mbox, dest, self) then r = false end
    end
    return r
end


function Set.select_all(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.select_all(mbox)
    end
    return self * set
end

function Set.send_query(self, criteria)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.send_query(mbox, criteria, self)
    end
    return self * set
end

function Set.is_answered(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_answered(mbox, self)
    end
    return self * set
end

function Set.is_deleted(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_deleted(mbox, self)
    end
    return self * set
end

function Set.is_draft(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_draft(mbox, self)
    end
    return self * set
end

function Set.is_flagged(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_flagged(mbox, self)
    end
    return self * set
end

function Set.is_new(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_new(mbox, self)
    end
    return self * set
end

function Set.is_old(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_old(mbox, self)
    end
    return self * set
end

function Set.is_recent(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_recent(mbox, self)
    end
    return self * set
end

function Set.is_seen(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_seen(mbox, self)
    end
    return self * set
end

function Set.is_unanswered(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_unanswered(mbox, self)
    end
    return self * set
end

function Set.is_undeleted(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_undeleted(mbox, self)
    end
    return self * set
end

function Set.is_undraft(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_undraft(mbox, self)
    end
    return self * set
end

function Set.is_unflagged(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_unflagged(mbox, self)
    end
    return self * set
end

function Set.is_unseen(self)
    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_unseen(mbox, self)
    end
    return self * set
end


function Set.has_keyword(self, flag)
    _check_required(flag, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.has_keyword(mbox, flag, self)
    end
    return self * set
end

Set.has_flag = Set.has_keyword

function Set.has_unkeyword(self, flag)
    _check_required(flag, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.has_unkeyword(mbox, flag, self)
    end
    return self * set
end


function Set.is_larger(self, size)
    _check_required(size, 'number')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_larger(mbox, size, self)
    end
    return self * set
end

function Set.is_smaller(self, size)
    _check_required(size, 'number')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_smaller(mbox, size, self)
    end
    return self * set
end


function Set.arrived_on(self, date)
    _check_required(date, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.arrived_on(mbox, date, self)
    end
    return self * set
end

function Set.arrived_before(self, date)
    _check_required(date, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.arrived_before(mbox, date, self)
    end
    return self * set
end

function Set.arrived_since(self, date)
    _check_required(date, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.arrived_since(mbox, date, self)
    end
    return self * set
end

function Set.sent_on(self, date)
    _check_required(date, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.sent_on(mbox, date, self)
    end
    return self * set
end

function Set.sent_before(self, date)
    _check_required(date, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.sent_before(mbox, date, self)
    end
    return self * set
end

function Set.sent_since(self, date)
    _check_required(date, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.sent_since(mbox, date, self)
    end
    return self * set
end

function Set.is_newer(self, days)
    _check_required(days, 'number')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_newer(mbox, days, self)
    end
    return self * set
end

function Set.is_older(self, days)
    _check_required(days, 'number')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.is_older(mbox, days, self)
    end
    return self * set
end


function Set.contain_field(self, field, string)
    _check_required(field, 'string')
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_field(mbox, field, string, self)
    end
    return self * set
end

function Set.contain_bcc(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_bcc(mbox, string, self)
    end
    return self * set
end

function Set.contain_cc(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_cc(mbox, string, self)
    end
    return self * set
end

function Set.contain_from(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_from(mbox, string, self)
    end
    return self * set
end

function Set.contain_subject(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_subject(mbox, string, self)
    end
    return self * set
end

function Set.contain_to(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_to(mbox, string, self)
    end
    return self * set
end

function Set.contain_header(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_header(mbox, string, self)
    end
    return self * set
end

function Set.contain_body(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_body(mbox, string, self)
    end
    return self * set
end

function Set.contain_message(self, string)
    _check_required(string, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.contain_message(mbox, string, self)
    end
    return self * set
end

function Set.match_bcc(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_bcc(mbox, pattern, self)
    end
    return self * set
end

function Set.match_cc(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_cc(mbox, pattern, self)
    end
    return self * set
end

function Set.match_from(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_from(mbox, pattern, self)
    end
    return self * set
end

function Set.match_subject(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_subject(mbox, pattern, self)
    end
    return self * set
end

function Set.match_to(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_to(mbox, pattern, self)
    end
    return self * set
end

function Set.match_field(self, field, pattern)
    _check_required(field, 'string')
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_field(mbox, field, pattern, self)
    end
    return self * set
end

function Set.match_header(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_header(mbox, pattern, self)
    end
    return self * set
end

function Set.match_body(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_body(mbox, pattern, self)
    end
    return self * set
end

function Set.match_message(self, pattern)
    _check_required(pattern, 'string')

    local set = Set()
    for mbox in pairs(_extract_mailboxes(self)) do
        set = set + mbox.match_message(mbox, pattern, self)
    end
    return self * set
end


Set._mt.__call = Set._new
