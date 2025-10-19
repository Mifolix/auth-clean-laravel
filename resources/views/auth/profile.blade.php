@extends('layouts.app')

@section('content')
    <div class="container">
        <h1>Профиль пользователя</h1>

        @if(session('status'))
            <div class="alert alert-success">{{ session('status') }}</div>
        @endif

        <form method="POST" action="{{ route('profile') }}">
            @csrf
            @method('PATCH')

            <div class="mb-3">
                <label for="name" class="form-label">Имя</label>
                <input type="text" class="form-control" id="name" name="name" value="{{ old('name', $user->name) }}" required>
            </div>

            <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" value="{{ old('email', $user->email) }}" required>
            </div>

            <button type="submit" class="btn btn-primary">Сохранить изменения</button>
        </form>

        <div class="mt-4">
            <a href="{{ route('changePassword') }}" class="btn btn-secondary">Изменить пароль</a>
        </div>
    </div>
@endsection
