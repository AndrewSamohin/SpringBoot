package com.example.tasklist.config;

import graphql.GraphQLContext;
import graphql.execution.CoercedVariables;
import graphql.language.StringValue;
import graphql.language.Value;
import graphql.schema.Coercing;
import graphql.schema.CoercingParseLiteralException;
import graphql.schema.CoercingParseValueException;
import graphql.schema.CoercingSerializeException;
import lombok.SneakyThrows;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Locale;

public class LocalDateTimeCoercing implements Coercing<LocalDateTime, String> {

    @Nullable
    @Override
    @SneakyThrows
    public String serialize(
            @NotNull Object dataFetcherResult,
            @NotNull GraphQLContext graphQLContext,
            @NotNull Locale locale
    ) throws CoercingSerializeException {
        SimpleDateFormat formatter
                = new SimpleDateFormat(
                        "yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.ENGLISH);
        return formatter.format(
                Date.from(((LocalDateTime) dataFetcherResult)
                        .atZone(ZoneId.systemDefault())
                        .toInstant())
        );
    }

    @Nullable
    @Override
    @SneakyThrows
    public LocalDateTime parseValue(
            @NotNull Object input,
            @NotNull GraphQLContext graphQLContext,
            @NotNull Locale locale
    ) throws CoercingParseValueException {
        return LocalDateTime.parse((String) input);
    }

    @Nullable
    @Override
    @SneakyThrows
    public LocalDateTime parseLiteral(
            @NotNull Value<?> input,
            @NotNull CoercedVariables variables,
            @NotNull GraphQLContext graphQLContext,
            @NotNull Locale locale
    ) throws CoercingParseLiteralException {
        return LocalDateTime.parse(((StringValue) input).getValue());
    }
}
