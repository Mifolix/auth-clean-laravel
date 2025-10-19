@extends('layouts.app')

@section('content')
    <div class="container">
        <h1>Изменение пароля</h1>

        @if ($errors->any())
            <div class="alert alert-danger">
                <ul>
                    @foreach ($errors->all() as $error)
                        <li>{{ $error }}</li>
                    @endforeach
                </ul>
            </div>
        @endif

        <form method="POST" action="{{ route('changePassword') }}">
            @csrf

            <div class="mb-3">
                <label for="current_password" class="form-label">Текущий пароль</label>
                <input type="password" class="form-control" id="current_password" name="current_password" required>
            </div>

            <div class="mb-3">
                <label for="new_password" class="form-label">Новый пароль</label>
                <input type="password" class="form-control" id="new_password" name="new_password" required>
            </div>

            <div class="mb-3">
                <label for="new_password_confirmation" class="form-label">Подтверждение нового пароля</label>
                <input type="password" class="form-control" id="new_password_confirmation" name="new_password_confirmation" required>
            </div>

            <button type="submit" class="btn btn-primary">Изменить пароль</button>
        </form>
    </div>
@endsection
