import python


predicate rootAndTail(Expr e, Name root, string tail) {
  e = root and tail = "" or
  exists(Attribute a, Name r, string t |
    e = a and rootAndTail(a.getObject(), r, t) and
    ( t = "" and tail = a.getName()
      or not t = "" and tail = t + "." + a.getName()
    )
  )
}

predicate fromImportRootToModule(Name n, Call callSite, string mod) {
  exists(ImportMember im |
    im.getName() = n.getId() and
    im.getLocation().getFile() = callSite.getLocation().getFile() and
    im.getLocation().getStartLine() <= callSite.getLocation().getStartLine() and
    mod = im.getImportedModuleName()
  )
}

predicate importAliasRootToModule(Name n, Call callSite, string mod) {
  exists(Import imp, Alias al, ImportExpr ie |
    imp.getAName() = al and
    al.getAsname() = n and
    al.getValue() = ie and
    imp.getLocation().getFile() = callSite.getLocation().getFile() and
    imp.getLocation().getStartLine() <= callSite.getLocation().getStartLine() and
    mod = ie.getImportedModuleName()
  )
}

predicate fromImportMemberAliasToFull(Name n, Call callSite, string full) {
  exists(Import imp, ImportMember im, string m |
    imp.getASubExpression() = im and
    im.getName() = n.getId() and
    imp.getLocation().getFile() = callSite.getLocation().getFile() and
    imp.getLocation().getStartLine() <= callSite.getLocation().getStartLine() and
    imp.getAnImportedModuleName() = m and m.regexpMatch("(^|.*\\.)join$") and
    full = m
  )
}

predicate canonicalJoin(Call c, string qn) {
  exists(Name n, string full |
    c.getFunc() = n and
    fromImportMemberAliasToFull(n, c, full) and
    qn = full
  )
  or
  exists(Attribute a, Name root, string tail, string base |
    c.getFunc() = a and
    a.getName() = "join" and
    rootAndTail(a, root, tail) and
    (
      fromImportRootToModule(root, c, base)
      or importAliasRootToModule(root, c, base)
      or base = root.getId()
    ) and
    (
      tail = ""        and qn = base
      or not tail = "" and qn = base
    )
  )
  or
  exists(Attribute a2 |
    c.getFunc() = a2 and a2.getName() = "join" and qn = a2.toString()
  )
}

from Function f, Call c, string qn
where f.contains(c) and canonicalJoin(c, qn) 
and qn.indexOf("os.path.join") = 0
select f.getName(), f.getLocation(), f.getLastStatement().getLocation(), "callee=" + qn
