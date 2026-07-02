### Example

```
$ cargo run --bin celast -- 'object.spec.replicas <= 10' object.spec.replicas:int
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.03s
     Running `/home/andrew/src/github.com/ajwdev/pallograph/.worktrees/cel-z3/target/debug/celast 'object.spec.replicas <= 10' 'object.spec.replicas:int'`
expr: object.spec.replicas <= 10

AST:
IdedExpr {
    id: 4,
    expr: Call(
        CallExpr {
            func_name: "_<=_",
            target: None,
            args: [
                IdedExpr {
                    id: 3,
                    expr: Select(
                        SelectExpr {
                            operand: IdedExpr {
                                id: 2,
                                expr: Select(
                                    SelectExpr {
                                        operand: IdedExpr {
                                            id: 1,
                                            expr: Ident(
                                                "object",
                                            ),
                                        },
                                        field: "spec",
                                        test: false,
                                    },
                                ),
                            },
                            field: "replicas",
                            test: false,
                        },
                    ),
                },
                IdedExpr {
                    id: 5,
                    expr: Literal(
                        Int(
                            Int(
                                10,
                            ),
                        ),
                    ),
                },
            ],
        },
    ),
}

Z3:
(<= object.spec.replicas 10)
```
